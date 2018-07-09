package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/containers/image/copy"
	"github.com/containers/image/docker"
	"github.com/containers/image/docker/reference"
	"github.com/containers/image/manifest"
	"github.com/containers/image/signature"
	"github.com/containers/image/transports"
	"github.com/containers/image/transports/alltransports"
	"github.com/containers/image/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func isValidTransport(transport types.ImageTransport) (bool, error) {
	dockerTransport := transports.Get("docker")
	if dockerTransport == nil {
		return false, fmt.Errorf("Cannot find 'docker' transport type")
	}

	dockerArchiveTransport := transports.Get("docker-archive")
	if dockerArchiveTransport == nil {
		return false, fmt.Errorf("Cannot find 'docker-archive' transport type")
	}

	validTransports := []types.ImageTransport{
		dockerTransport,
		dockerArchiveTransport,
	}

	for _, vt := range validTransports {
		if transport == vt {
			return true, nil
		}
	}

	return false, nil
}

func getImageReference(imgName string) (types.ImageReference, error) {
	ref, err := alltransports.ParseImageName(imgName)
	if err != nil {
		return nil, fmt.Errorf("Invalid image name %s: %v", imgName, err)
	}
	valid, err := isValidTransport(ref.Transport())
	if !valid {
		return nil, fmt.Errorf("Invalid transport")
	}
	if err != nil {
		return nil, err
	}

	return ref, nil
}

// Builds the final destination of the image:
// eg: given destination `docker://my-registry.local.lan` and src `docker://docker.io/busybox:stable`
// the final destination is going to be docker://my-registry.local.lan/docker.io/busybox:
func buildFinalDestination(srcRef types.ImageReference, globalDest string) (destRef types.ImageReference, err error) {
	dst := fmt.Sprintf("%s/%s", globalDest, srcRef.DockerReference())

	return getImageReference(dst)
}

func getImageTags(ctx context.Context, sysCtx *types.SystemContext, imgRef types.ImageReference) (tags []string, retErr error) {
	img, err := imgRef.NewImage(ctx, sysCtx)
	if err != nil {
		return tags, err
	}
	defer func() {
		if err := img.Close(); err != nil {
			retErr = errors.Wrapf(retErr, fmt.Sprintf("(could not close image: %v) ", err))
		}
	}()
	if dockerImg, ok := img.(*docker.Image); ok {
		logrus.WithFields(logrus.Fields{
			"image": dockerImg.SourceRefFullName(),
		}).Info("Getting tags")
		tags, retErr = dockerImg.GetRepositoryTags(context.Background())
		if retErr != nil {
			// some registries may decide to block the "list all tags" endpoint
			// gracefully allow the inspect to continue in this case. Currently
			// the IBM Bluemix container registry has this restriction.
			if !strings.Contains(retErr.Error(), "401") {
				return tags, fmt.Errorf("Error determining repository tags: %v", retErr)
			}
			logrus.Warn("Registry disallows tag list retrieval; skipping")
		}
	}

	return
}

// Return true if the image had a tag specified, false otherwise
func isTagSpecified(image string) (bool, error) {
	if strings.HasSuffix(image, ":latest") {
		return true, nil
	}

	// Normalize the image name, this will automatically add
	// the `latest` tag when no tag has been specified
	normName, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return true, err
	}

	// if the tag is `latest` -> the tag has been automatically added -> no tag
	// was specified by the user
	return !strings.HasSuffix(reference.TagNameOnly(normName).String(), ":latest"), nil
}
func syncSourceHandler(c *cli.Context, policyContext *signature.PolicyContext, globalDestRef types.ImageReference, options *copy.Options) (retErr error) {
	srcRef, err := getImageReference(c.String("source"))
	if err != nil {
		return fmt.Errorf("Error while parsing source: %v", err)
	}

	sourceCtx, err := contextFromGlobalOptions(c, "src-")
	if err != nil {
		return err
	}
	options.SourceCtx = sourceCtx

	if srcRef.Transport() != transports.Get("docker") {
		// TODO: handle dir transport
		return nil
	}

	sourceReferences := []types.ImageReference{}
	imageTagged, err := isTagSpecified(strings.TrimPrefix(c.String("source"), "docker://"))
	if err != nil {
		return err
	}
	if imageTagged {
		sourceReferences = append(sourceReferences, srcRef)
	} else {
		tags, err := getImageTags(context.Background(), sourceCtx, srcRef)
		if err != nil {
			return fmt.Errorf("Error while retrieving available tags of %s: %v",
				c.String("source"),
				err)
		}
		for _, tag := range tags {
			imageAndTag := fmt.Sprintf("%s:%s", c.String("source"), tag)
			ref, err := getImageReference(imageAndTag)
			if err != nil {
				return fmt.Errorf("Error while building reference of %s: %v",
					imageAndTag,
					err)
			}
			sourceReferences = append(sourceReferences, ref)
		}
	}

	for counter, ref := range sourceReferences {
		fmt.Printf("Processing image %d/%d\n",
			counter+1,
			len(sourceReferences))
		destRef, err := buildFinalDestination(ref, c.Args()[0])
		if err != nil {
			return err
		}
		logrus.WithFields(logrus.Fields{
			"source":      ref,
			"destination": destRef,
		}).Debug("Copy started")

		err = copy.Image(context.Background(), policyContext, destRef, ref, options)
		if err != nil {
			return err
		}
	}

	return nil
}

func syncHandler(c *cli.Context) (retErr error) {
	if len(c.Args()) != 1 {
		cli.ShowCommandHelp(c, "sync")
		return errors.New("Exactly one argument expected")
	}

	if c.IsSet("source") && c.IsSet("source-file") {
		return fmt.Errorf(
			"Cannot use the '--source' and '--source-file' flags at the same time")
	}

	if !c.IsSet("source") && !c.IsSet("source-file") {
		return fmt.Errorf(
			"Must specify either a '--source' or a '--source-file'")
	}

	policyContext, err := getPolicyContext(c)
	if err != nil {
		return fmt.Errorf("Error loading trust policy: %v", err)
	}
	defer policyContext.Destroy()

	destRef, err := getImageReference(c.Args()[0])
	if err != nil {
		return fmt.Errorf("Error while parsing destination: %v", err)
	}
	destinationCtx, err := contextFromGlobalOptions(c, "dest-")
	if err != nil {
		return err
	}

	signBy := c.String("sign-by")
	removeSignatures := c.Bool("remove-signatures")

	//TODO: should we assume that's our default manifest type?
	manifestType := manifest.DockerV2Schema2MediaType

	copyOptions := copy.Options{
		RemoveSignatures:      removeSignatures,
		SignBy:                signBy,
		ReportWriter:          os.Stdout,
		DestinationCtx:        destinationCtx,
		ForceManifestMIMEType: manifestType,
	}

	if c.IsSet("source") {
		return syncSourceHandler(
			c,
			policyContext,
			destRef,
			&copyOptions,
		)
	}
	return nil
}

var syncCmd = cli.Command{
	Name:  "sync",
	Usage: "Sync one or more images from one location to another",
	Description: fmt.Sprint(`

	Copy all the images from SOURCE to DESTINATION.

	Useful to keep in sync a local docker registry mirror. Can be used
	to populate also registries running inside of air-gapped environments.

	SOURCE can be either a repository hosted on a docker registry
	(eg: docker://docker.io/busybox) or a local directory
	(eg: dir:///media/usb/). Note well: no image tag has to be specified when
	SOURCE is referencing a hosted repository.

	When SOURCE is a repository hosted on a docker registry all the
	tags of the repository are going to be copied into DESTINATION.

	DESTINATION can be either a docker registry
	(eg: docker://my-registry.local.lan) or a local directory
	(eg: dir:///media/usb). When DESTINATION is a local directory one
	file per image is going to be created.
	`),
	ArgsUsage: "[--source SOURCE] [--source-file SOURCE-FILE] DESTINATION",
	Action:    syncHandler,
	// FIXME: Do we need to namespace the GPG aspect?
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "authfile",
			Usage: "path of the authentication file. Default is ${XDG_RUNTIME_DIR}/containers/auth.json",
		},
		cli.BoolFlag{
			Name:  "remove-signatures",
			Usage: "Do not copy signatures from SOURCE images",
		},
		cli.StringFlag{
			Name:  "sign-by",
			Usage: "Sign the image using a GPG key with the specified `FINGERPRINT`",
		},
		cli.StringFlag{
			Name:  "source",
			Value: "",
			Usage: "The SOURCE from which images are going to be copied",
		},
		cli.StringFlag{
			Name:  "source-file",
			Value: "",
			Usage: "YAML file with the images to be copied",
		},
		cli.StringFlag{
			Name:  "src-creds, screds",
			Value: "",
			Usage: "Use `USERNAME[:PASSWORD]` for accessing the source registry",
		},
		cli.StringFlag{
			Name:  "dest-creds, dcreds",
			Value: "",
			Usage: "Use `USERNAME[:PASSWORD]` for accessing the destination registry",
		},
		cli.StringFlag{
			Name:  "src-cert-dir",
			Value: "",
			Usage: "use certificates at `PATH` (*.crt, *.cert, *.key) to connect to the source registry or daemon",
		},
		cli.BoolTFlag{
			Name:  "src-tls-verify",
			Usage: "require HTTPS and verify certificates when talking to the container source registry or daemon (defaults to true)",
		},
		cli.StringFlag{
			Name:  "dest-cert-dir",
			Value: "",
			Usage: "use certificates at `PATH` (*.crt, *.cert, *.key) to connect to the destination registry or daemon",
		},
		cli.BoolTFlag{
			Name:  "dest-tls-verify",
			Usage: "require HTTPS and verify certificates when talking to the container destination registry or daemon (defaults to true)",
		},
	},
}
