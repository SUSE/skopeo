package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	//"path/filepath"
	"strings"
	"runtime"
	"time"
	"math"

	"github.com/containers/image/copy"
	"github.com/containers/image/directory"
	"github.com/containers/image/docker"
	//"github.com/containers/image/docker/reference"
	"github.com/containers/image/transports"
	"github.com/containers/image/types"
	"github.com/containers/image/signature"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var MAX_THREADS int = int( math.Min(float64(runtime.NumCPU()), 4.0))

type registrySyncOptions struct {
	global            *globalOptions
	srcImage          *imageOptions
	destImage         *imageDestOptions
	removeSignatures  bool   // Do not copy signatures from the source image
	signByFingerprint string // Sign the image using a GPG key with the specified fingerprint
	sourceYaml        bool
}

type registryregistrySyncCfg struct {
	Images      map[string][]string
	Credentials types.DockerAuthConfig
	TLSVerify   tlsVerifyConfig `yaml:"tls-verify"`
	CertDir     string          `yaml:"cert-dir"`
}

// Checks if a given transport is supported by the registrySync operation.
func validregistrySyncTransport(transport types.ImageTransport) bool {
	switch transport {
	case docker.Transport:
		return true
	case directory.Transport:
		return true
	}

	return false
}

// Given a source URL and context, returns a list of tagged image references to
// be used as registrySync source.
func registrySyncFromURL(sourceURL *url.URL, sourceCtx *types.SystemContext) (repoDescriptor, error) {
	repoDesc := repoDescriptor{
		Context: sourceCtx,
	}

	switch transports.Get(sourceURL.Scheme) {
	case docker.Transport:
		srcRef, err := getImageReference(docker.Transport, fmt.Sprintf("//%s%s", sourceURL.Host, sourceURL.Path))
		if err != nil {
			return repoDesc, errors.WithMessage(err, "Error while parsing destination")
		}

		imageTagged, err := isTagSpecified(sourceURL.Host + sourceURL.Path)
		if err != nil {
			return repoDesc, err
		}
		if imageTagged {
			repoDesc.TaggedImages = append(repoDesc.TaggedImages, srcRef)
			break
		}

		repoName := fmt.Sprintf("//%s", path.Join(sourceURL.Host, sourceURL.Path))
		repoDesc.TaggedImages, err = imagesToCopyFromRegistry(srcRef, repoName, sourceCtx)
		if err != nil {
			return repoDesc, err
		}
	case directory.Transport:
		dirPath, err := dirPathFromURL(sourceURL)
		if err != nil {
			return repoDesc, errors.WithMessage(err, "Error processing source URL")
		}

		repoDesc.DirBasePath = dirPath
		repoDesc.TaggedImages, err = imagesToCopyFromDir(dirPath)
		if err != nil {
			return repoDesc, err
		}
	}

	if len(repoDesc.TaggedImages) == 0 {
		return repoDesc, errors.New("No images to registrySync found in SOURCE")
	}

	return repoDesc, nil
}

type imageCollectChannel struct {
	repoDesc repoDescriptor
	err error
}

func registryCollectTagsForImage(imageName string, server string, tags []string, serverCtx *types.SystemContext, iCC chan imageCollectChannel) {
	repoName := fmt.Sprintf("//%s", path.Join(server, imageName))
	logrus.WithFields(logrus.Fields{
		"repo":     imageName,
		"registry": server,
	}).Info("Processing repo")

	var err error

	var sourceReferences []types.ImageReference
	for _, tag := range tags {
		source := fmt.Sprintf("%s:%s", repoName, tag)

		imageRef, err := docker.ParseReference(source)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"tag": source,
			}).Error("Error processing tag, skipping")
			logrus.Errorf("Error getting image reference: %s", err)
			continue
		}
		sourceReferences = append(sourceReferences, imageRef)
	}

	if len(tags) == 0 {
		logrus.WithFields(logrus.Fields{
			"repo":     imageName,
			"registry": server,
		}).Info("Querying registry for image tags")

		imageRef, err := docker.ParseReference(repoName)
		if err != nil {
			iCC <- imageCollectChannel{
				repoDescriptor{},
				err}

			return
		}

		sourceReferences, err = imagesToCopyFromRegistry(imageRef, repoName, serverCtx)
		if err != nil {
			iCC <- imageCollectChannel{
				repoDescriptor{},
				err}

			return
		}
	}

	if len(sourceReferences) == 0 {
		logrus.WithFields(logrus.Fields{
			"repo":     imageName,
			"registry": server,
		}).Warnf("No tags to sync found")

		err = errors.New("No tags to sync found")
	}

	iCC <- imageCollectChannel{
		repoDescriptor{
			TaggedImages: sourceReferences,
			Context:      serverCtx},
			err}
}

// Given a yaml file and a source context, returns a list of repository descriptors,
// each containing a list of tagged image references, to be used as registrySync source.
func registrySyncFromYaml(yamlFile string, sourceCtx *types.SystemContext) (repoDescList []repoDescriptor, err error) {
	fmt.Println( "File: ", yamlFile )
	cfg, err := newSourceConfig(yamlFile)

	if err != nil {
		return
	}

	fmt.Println( "Parsed: ", cfg )

	for server, serverCfg := range cfg {
		if len(serverCfg.Images) == 0 {
			logrus.WithFields(logrus.Fields{
				"registry": server,
			}).Warn("No images specified for registry")
			continue
		}

		var cs = make([]chan imageCollectChannel, 0, MAX_THREADS)
		for imageName, tags := range serverCfg.Images {
			serverCtx := sourceCtx
			// override ctx with per-server options
			serverCtx.DockerCertPath = serverCfg.CertDir
			serverCtx.DockerDaemonCertPath = serverCfg.CertDir
			serverCtx.DockerDaemonInsecureSkipTLSVerify = serverCfg.TLSVerify.skip
			serverCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(serverCfg.TLSVerify.skip)
			serverCtx.DockerAuthConfig = &serverCfg.Credentials

			cs = append(cs, make(chan imageCollectChannel))

			go registryCollectTagsForImage(imageName, server, tags, serverCtx, cs[ len(cs) - 1])

			for cap( cs ) == len( cs ) {
				time.Sleep(10 * time.Millisecond)

				for i := 0; i < len( cs ); i += 1 {
					select {
					case iCC := <-cs[ i ]:
						cs[ i ] = cs[ len( cs ) - 1 ]
						cs = cs[ :len( cs ) -1 ]
						i -= 1

						if iCC.err != nil {
							logrus.WithFields(logrus.Fields{
								"repo":     imageName,
								"registry": server,
							}).Error("Error processing repo, skipping")
							logrus.Error(err)
							continue
						}

						repoDescList = append(repoDescList, iCC.repoDesc)
					default:
						continue
					}
				}
			}
		}
	}

	return
}

type copyImageTagChannel struct {
	done bool
	err error
}

type copyImageTagOptions struct {
	counter int
	imageRef types.ImageReference
	destinationURL *url.URL
	srcRepo repoDescriptor
	ctx context.Context
	policyContext *signature.PolicyContext
	options copy.Options
	cITC chan copyImageTagChannel
}

func copyImageTag(opts copyImageTagOptions) {
	retryCount := 0
	Retry: for {
		destRef, err := buildFinalDestination(opts.imageRef, opts.destinationURL, opts.srcRepo.DirBasePath)
		if err != nil {
			opts.cITC <-copyImageTagChannel{ false, err }
			return
		}

		logrus.WithFields(logrus.Fields{
			"from": transports.ImageName(opts.imageRef),
			"to":   transports.ImageName(destRef),
		}).Infof("Copying image tag %d/%d", opts.counter+1, len(opts.srcRepo.TaggedImages))

		// copy.Image - this has the uuid of the tag, and is where history will
		//  need to be add
		_, err = copy.Image(opts.ctx, opts.policyContext, destRef, opts.imageRef, &opts.options)
		if err != nil {
			logrus.Error(errors.WithMessage(err, fmt.Sprintf("Error copying tag '%s'", transports.ImageName(opts.imageRef))))

			fmt.Println( "Retry: ", retryCount )
			if retryCount < 3 {
				continue Retry
			}

			retryCount += 1
		}

		break
	}

	opts.cITC <-copyImageTagChannel{ true, nil }
}

func (opts *registrySyncOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 2 {
		return errorShouldDisplayUsage{errors.New("Exactly two arguments expected")}
	}

	policyContext, err := opts.global.getPolicyContext()
	if err != nil {
		return errors.WithMessage(err, "Error loading trust policy")
	}
	defer policyContext.Destroy()

	destinationURL, err := parseURL(args[1])
	if err != nil {
		return errors.WithMessage(err, "Error while parsing destination")
	}
	destinationCtx, err := opts.destImage.newSystemContext()
	if err != nil {
		return err
	}

	//fmt.Println( "destinationCtx: ", destinationCtx )
	// destinationCtx:  &{        []  false  false   0 <nil>  false    false false}

	sourceCtx, err := opts.srcImage.newSystemContext()
	if err != nil {
		return err
	}
	sourceArg := args[0]

	var srcRepoList []repoDescriptor

	if opts.sourceYaml {
		srcRepoList, err = registrySyncFromYaml(sourceArg, sourceCtx)
		if err != nil {
			return err
		}
	} else {
		sourceURL, err := parseURL(sourceArg)
		if err != nil {
			return errors.WithMessage(err, "Error while parsing source")
		}

		if transports.Get(sourceURL.Scheme) == directory.Transport &&
			sourceURL.Scheme == destinationURL.Scheme {
			return errors.New("registry-sync from 'dir:' to 'dir:' not implemented, use something like rregistrySync instead")
		}

		srcRepo, err := registrySyncFromURL(sourceURL, sourceCtx)
		if err != nil {
			return err
		}
		srcRepoList = append(srcRepoList, srcRepo)
	}

	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	var imgCounter int
	for _, srcRepo := range srcRepoList {
		options := copy.Options{
			RemoveSignatures: opts.removeSignatures,
			SignBy:           opts.signByFingerprint,
			ReportWriter:     os.Stdout,
			DestinationCtx:   destinationCtx,
			SourceCtx:        srcRepo.Context,
		}

		// I want a pool of "processes" to hand a set of tags in parallel
		var cs = make([]chan copyImageTagChannel, 0, MAX_THREADS)

		for counter, ref := range srcRepo.TaggedImages {
			cs = append(cs, make(chan copyImageTagChannel))

			options := copyImageTagOptions {counter, ref, destinationURL, srcRepo, ctx, policyContext, options, cs[ len(cs) - 1]}

			go copyImageTag(options)

			for cap( cs ) == len( cs ) {
				time.Sleep(10 * time.Millisecond)

				for i := 0; i < len( cs ); i += 1 {
					select {
					case cITC := <-cs[ i ]:
						cs[ i ] = cs[ len( cs ) - 1 ]
						cs = cs[ :len( cs ) -1 ]
						i -= 1

						if cITC.err != nil {}
					default:
						continue
					}
				}
			}
			imgCounter++
		}
	}

	logrus.Infof("registry-synced %d images from %d sources", imgCounter, len(srcRepoList))

	return nil
}

func registrySyncCmd(global *globalOptions) cli.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	srcFlags, srcOpts := imageFlags(global, sharedOpts, "src-", "screds")
	destFlags, destOpts := imageDestFlags(global, sharedOpts, "dest-", "dcreds")
	opts := registrySyncOptions{global: global,
		srcImage:  srcOpts,
		destImage: destOpts,
	}

	filterFlags := func(flags []cli.Flag, prefix string) []cli.Flag {
		flagsNotNeeded := []string{
			"daemon-host",
			"ostree-tmp-dir",
			"shared-blob-dir",
		}

		filtered := flags[:0]
		for _, f := range flags {
			var found bool
			for _, e := range flagsNotNeeded {
				if e == strings.TrimPrefix(f.GetName(), prefix) {
					found = true
					break
				}
			}
			if !found {
				filtered = append(filtered, f)
			}
		}
		return filtered
	}

	srcFlags = filterFlags(srcFlags, "src-")
	destFlags = filterFlags(destFlags, "dest-")

	return cli.Command{
		Name:  "registry-sync",
		Usage: "registry-sync one or more images from one location to another",
		Description: fmt.Sprint(`

	Copy all the images from SOURCE to DESTINATION.

	Useful to keep in sync a local container registry mirror. Can be used
	to populate also registries running inside of air-gapped environments.

	SOURCE can be either a repository hosted on a container registry
	(eg: docker://registry.example.com/busybox) or a local directory
	(eg: dir:/media/usb/).

	If --source-yaml is specified, then SOURCE points to a YAML file with
	a list of source images from different container registries
	(local directories are not supported).

	When syncing from a repository where no tags are specified, skopeo
	registry-sync will copy all the tags contained in that repository.

	DESTINATION can be either a container registry
	(eg: docker://my-registry.local.lan) or a local directory
	(eg: dir:/media/usb).

	When DESTINATION is a local directory, one directory per 'image:tag' is going
	to be created.
	`),
		ArgsUsage: "[--source-yaml] SOURCE DESTINATION",
		Action:    commandAction(opts.run),
		// FIXME: Do we need to namespace the GPG aspect?
		Flags: append(append(append([]cli.Flag{
			cli.BoolFlag{
				Name:        "remove-signatures",
				Usage:       "Do not copy signatures from SOURCE images",
				Destination: &opts.removeSignatures,
			},
			cli.StringFlag{
				Name:        "sign-by",
				Usage:       "Sign the image using a GPG key with the specified `FINGERPRINT`",
				Destination: &opts.signByFingerprint,
			},
			cli.BoolFlag{
				Name:        "source-yaml",
				Usage:       "Interpret SOURCE as a YAML file with a list of images from different container registries",
				Destination: &opts.sourceYaml,
			},
		}, sharedFlags...), srcFlags...), destFlags...),
	}
}
