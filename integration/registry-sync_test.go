package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/containers/image/docker"
	"github.com/containers/image/types"
	"github.com/go-check/check"
)

func init() {
	check.Suite(&SyncSuite{})
}

type SyncSuite struct {
	cluster  *openshiftCluster
	registry *testRegistryV2
	gpgHome  string
}

func (s *SyncSuite) SetUpSuite(c *check.C) {
	const registryAuth = false
	const registrySchema1 = false

	if os.Getenv("SKOPEO_LOCAL_TESTS") == "1" {
		c.Log("Running tests without a container")
		fmt.Printf("NOTE: tests requires a V2 registry at url=%s, with auth=%t, schema1=%t \n", v2DockerRegistryURL, registryAuth, registrySchema1)
		return
	}

	if os.Getenv("SKOPEO_CONTAINER_TESTS") != "1" {
		c.Skip("Not running in a container, refusing to affect user state")
	}

	s.cluster = startOpenshiftCluster(c) // FIXME: Set up TLS for the docker registry port instead of using "--tls-verify=false" all over the place.

	for _, stream := range []string{"unsigned", "personal", "official", "naming", "cosigned", "compression", "schema1", "schema2"} {
		isJSON := fmt.Sprintf(`{
			"kind": "ImageStream",
			"apiVersion": "v1",
			"metadata": {
			    "name": "%s"
			},
			"spec": {}
		}`, stream)
		runCommandWithInput(c, isJSON, "oc", "create", "-f", "-")
	}

	// FIXME: Set up TLS for the docker registry port instead of using "--tls-verify=false" all over the place.
	s.registry = setupRegistryV2At(c, v2DockerRegistryURL, registryAuth, registrySchema1)

	gpgHome, err := ioutil.TempDir("", "skopeo-gpg")
	c.Assert(err, check.IsNil)
	s.gpgHome = gpgHome
	os.Setenv("GNUPGHOME", s.gpgHome)

	for _, key := range []string{"personal", "official"} {
		batchInput := fmt.Sprintf("Key-Type: RSA\nName-Real: Test key - %s\nName-email: %s@example.com\n%%commit\n",
			key, key)
		runCommandWithInput(c, batchInput, gpgBinary, "--batch", "--gen-key")

		out := combinedOutputOfCommand(c, gpgBinary, "--armor", "--export", fmt.Sprintf("%s@example.com", key))
		err := ioutil.WriteFile(filepath.Join(s.gpgHome, fmt.Sprintf("%s-pubkey.gpg", key)),
			[]byte(out), 0600)
		c.Assert(err, check.IsNil)
	}
}

func (s *SyncSuite) TearDownSuite(c *check.C) {
	if os.Getenv("SKOPEO_LOCAL_TESTS") == "1" {
		return
	}

	if s.gpgHome != "" {
		os.RemoveAll(s.gpgHome)
	}
	if s.registry != nil {
		s.registry.Close()
	}
	if s.cluster != nil {
		s.cluster.tearDown(c)
	}
}

func (s *SyncSuite) TestSyncDocker2DirTagged(c *check.C) {
	const localRegURL = "docker://" + v2DockerRegistryURL + "/"

	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)

	// FIXME: It would be nice to use one of the local Docker registries instead of neeeding an Internet connection.
	image := "busybox:latest"
	imageRef, err := docker.ParseReference(fmt.Sprintf("//%s", image))
	c.Assert(err, check.IsNil)
	imagePath := imageRef.DockerReference().String()

	dir1 := path.Join(tmpDir, "dir1")
	dir2 := path.Join(tmpDir, "dir2")

	// sync docker => dir
	assertSkopeoSucceeds(c, "", "sync", "docker://"+image, "dir:"+dir1)
	_, err = os.Stat(path.Join(dir1, imagePath, "manifest.json"))
	c.Assert(err, check.IsNil)

	// copy docker => dir
	assertSkopeoSucceeds(c, "", "copy", "docker://"+image, "dir:"+dir2)
	_, err = os.Stat(path.Join(dir2, "manifest.json"))
	c.Assert(err, check.IsNil)

	out := combinedOutputOfCommand(c, "diff", "-urN", path.Join(dir1, imagePath), dir2)
	c.Assert(out, check.Equals, "")
}

func (s *SyncSuite) TestSyncDirInterpretation(c *check.C) {
	const localRegURL = "docker://" + v2DockerRegistryURL + "/"

	// FIXME: It would be nice to use one of the local Docker registries instead of neeeding an Internet connection.
	image := "busybox:latest"
	imageRef, err := docker.ParseReference(fmt.Sprintf("//%s", image))
	c.Assert(err, check.IsNil)
	imagePath := imageRef.DockerReference().String()

	// format dir:/
	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	assertSkopeoSucceeds(c, "", "sync", "docker://"+image, "dir:"+tmpDir)
	_, err = os.Stat(path.Join(tmpDir, imagePath, "manifest.json"))
	c.Assert(err, check.IsNil)
	os.RemoveAll(tmpDir)

	// format dir:/
	tmpDir, err = ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	assertSkopeoSucceeds(c, "", "sync", "docker://"+image, "dir:/"+tmpDir)
	_, err = os.Stat(path.Join(tmpDir, imagePath, "manifest.json"))
	c.Assert(err, check.IsNil)
	os.RemoveAll(tmpDir)

	// format dir:///
	tmpDir, err = ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	assertSkopeoSucceeds(c, "", "sync", "docker://"+image, "dir://"+tmpDir)
	_, err = os.Stat(path.Join(tmpDir, imagePath, "manifest.json"))
	c.Assert(err, check.IsNil)
	os.RemoveAll(tmpDir)

	prefixes := []string{
		"localfolder",
		"directory.com",
		"directory.com:1234",
	}

	for _, p := range prefixes {
		os.RemoveAll(p)
		err = os.Mkdir(p, 0755)
		c.Assert(err, check.IsNil)

		// test as relative
		tmpDir, err = ioutil.TempDir(p, "skopeo-sync-test")
		c.Assert(err, check.IsNil)
		assertSkopeoSucceeds(c, "", "sync", "docker://"+image, "dir:"+tmpDir)
		_, err = os.Stat(path.Join(tmpDir, imagePath, "manifest.json"))
		c.Assert(err, check.IsNil)
		os.RemoveAll(tmpDir)
		os.RemoveAll(p)
	}
}

func (s *SyncSuite) TestSyncDocker2DirUntagged(c *check.C) {
	const localRegURL = "docker://" + v2DockerRegistryURL + "/"

	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)

	// FIXME: It would be nice to use one of the local Docker registries instead of neeeding an Internet connection.
	image := "alpine"
	imageRef, err := docker.ParseReference(fmt.Sprintf("//%s", image))
	c.Assert(err, check.IsNil)
	imagePath := imageRef.DockerReference().String()

	dir1 := path.Join(tmpDir, "dir1")
	assertSkopeoSucceeds(c, "", "sync", "docker://"+image, "dir:"+dir1)

	sysCtx := types.SystemContext{}
	tags, err := docker.GetRepositoryTags(context.Background(), &sysCtx, imageRef)
	c.Assert(err, check.IsNil)
	c.Check(len(tags), check.Not(check.Equals), 0)

	nManifests, err := filepath.Glob(path.Join(dir1, path.Dir(imagePath), "*", "manifest.json"))
	c.Assert(err, check.IsNil)
	c.Assert(len(nManifests), check.Equals, len(tags))
}

func (s *SyncSuite) TestSyncYamlUntagged(c *check.C) {
	const localRegURL = "docker://" + v2DockerRegistryURL + "/"
	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)
	dir1 := path.Join(tmpDir, "dir1")

	image := "alpine"
	imageRef, err := docker.ParseReference(fmt.Sprintf("//%s", image))
	c.Assert(err, check.IsNil)
	imagePath := imageRef.DockerReference().Name()

	sysCtx := types.SystemContext{}
	tags, err := docker.GetRepositoryTags(context.Background(), &sysCtx, imageRef)
	c.Assert(err, check.IsNil)
	c.Check(len(tags), check.Not(check.Equals), 0)

	yamlConfig := fmt.Sprintf(`
docker.io:
  images:
    %s:
`, image)

	//sync to the local reg
	yamlFile := path.Join(tmpDir, "registries.yaml")
	ioutil.WriteFile(yamlFile, []byte(yamlConfig), 0644)
	assertSkopeoSucceeds(c, "", "sync", "--source-yaml", "--dest-tls-verify=false", yamlFile, localRegURL)

	// sync back from local reg to a folder
	os.Remove(yamlFile)
	yamlConfig = fmt.Sprintf(`
%s:
  tls-verify: false
  images:
    %s:

`, v2DockerRegistryURL, imagePath)

	ioutil.WriteFile(yamlFile, []byte(yamlConfig), 0644)
	assertSkopeoSucceeds(c, "", "sync", "--source-yaml", yamlFile, "dir:"+dir1)

	sysCtx = types.SystemContext{
		DockerInsecureSkipTLSVerify: types.NewOptionalBool(true),
	}
	localTags, err := docker.GetRepositoryTags(context.Background(), &sysCtx, imageRef)
	c.Assert(err, check.IsNil)
	c.Check(len(localTags), check.Not(check.Equals), 0)
	c.Assert(len(localTags), check.Equals, len(tags))

	nManifests := 0
	//count the number of manifest.json in dir1
	err = filepath.Walk(dir1, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "manifest.json" {
			nManifests++
			return filepath.SkipDir
		}
		return nil
	})
	c.Assert(err, check.IsNil)
	c.Assert(nManifests, check.Equals, len(tags))
}

func (s *SyncSuite) TestSyncYaml2Dir(c *check.C) {
	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)
	dir1 := path.Join(tmpDir, "dir1")

	yamlConfig := `
docker.io:
  images:
    busybox:
      - latest
      - musl
    alpine:
      - edge
      - 3.8

    opensuse/leap:
      - latest

quay.io:
  images:
      quay/busybox:
          - latest`

	// get the number of tags
	re := regexp.MustCompile(`^ +- +[^:/ ]+`)
	var nTags int
	for _, l := range strings.Split(yamlConfig, "\n") {
		if re.MatchString(l) {
			nTags++
		}
	}
	c.Assert(nTags, check.Not(check.Equals), 0)

	yamlFile := path.Join(tmpDir, "registries.yaml")
	ioutil.WriteFile(yamlFile, []byte(yamlConfig), 0644)
	assertSkopeoSucceeds(c, "", "sync", "--source-yaml", yamlFile, "dir:"+dir1)

	nManifests := 0
	err = filepath.Walk(dir1, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "manifest.json" {
			nManifests++
			return filepath.SkipDir
		}
		return nil
	})
	c.Assert(err, check.IsNil)
	c.Assert(nManifests, check.Equals, nTags)
}

func (s *SyncSuite) TestSyncYamlTLSVerify(c *check.C) {
	const localRegURL = "docker://" + v2DockerRegistryURL + "/"
	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)
	dir1 := path.Join(tmpDir, "dir1")
	image := "busybox"
	tag := "latest"

	// FIXME: It would be nice to use one of the local Docker registries instead of neeeding an Internet connection.
	// copy docker => docker
	assertSkopeoSucceeds(c, "", "copy", "--dest-tls-verify=false", "docker://"+image+":"+tag, localRegURL+image+":"+tag)

	yamlTemplate := `
%s:
  %s
  images:
    %s:
      - %s`

	testCfg := []struct {
		tlsVerify string
		msg       string
		checker   func(c *check.C, regexp string, args ...string)
	}{
		{
			tlsVerify: "tls-verify: false",
			msg:       "",
			checker:   assertSkopeoSucceeds,
		},
		{
			tlsVerify: "tls-verify: true",
			msg:       ".*server gave HTTP response to HTTPS client.*",
			checker:   assertSkopeoFails,
		},
		// no "tls-verify" line means default TLS verify must be ON
		{
			tlsVerify: "",
			msg:       ".*server gave HTTP response to HTTPS client.*",
			checker:   assertSkopeoFails,
		},
	}

	for _, cfg := range testCfg {
		yamlConfig := fmt.Sprintf(yamlTemplate, v2DockerRegistryURL, cfg.tlsVerify, image, tag)
		yamlFile := path.Join(tmpDir, "registries.yaml")
		ioutil.WriteFile(yamlFile, []byte(yamlConfig), 0644)

		cfg.checker(c, cfg.msg, "sync", "--source-yaml", yamlFile, "dir:"+dir1)

		os.Remove(yamlFile)
	}

}

func (s *SyncSuite) TestSyncDocker2DockerTagged(c *check.C) {
	const localRegURL = "docker://" + v2DockerRegistryURL + "/"

	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)

	// FIXME: It would be nice to use one of the local Docker registries instead of neeeding an Internet connection.
	image := "busybox:latest"
	imageRef, err := docker.ParseReference(fmt.Sprintf("//%s", image))
	c.Assert(err, check.IsNil)
	imagePath := imageRef.DockerReference().String()

	dir1 := path.Join(tmpDir, "dir1")
	dir2 := path.Join(tmpDir, "dir2")

	// sync docker => docker
	assertSkopeoSucceeds(c, "", "sync", "--dest-tls-verify=false", "docker://"+image, localRegURL)

	// copy docker => dir
	assertSkopeoSucceeds(c, "", "copy", "docker://"+image, "dir:"+dir1)
	_, err = os.Stat(path.Join(dir1, "manifest.json"))
	c.Assert(err, check.IsNil)

	// copy docker => dir
	assertSkopeoSucceeds(c, "", "copy", "--src-tls-verify=false", localRegURL+imagePath, "dir:"+dir2)
	_, err = os.Stat(path.Join(dir2, "manifest.json"))
	c.Assert(err, check.IsNil)

	out := combinedOutputOfCommand(c, "diff", "-urN", dir1, dir2)
	c.Assert(out, check.Equals, "")
}

func (s *SyncSuite) TestSyncDir2DockerTagged(c *check.C) {
	const localRegURL = "docker://" + v2DockerRegistryURL + "/"

	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)

	// FIXME: It would be nice to use one of the local Docker registries instead of neeeding an Internet connection.
	image := "busybox:latest"

	dir1 := path.Join(tmpDir, "dir1")
	err = os.Mkdir(dir1, 0755)
	c.Assert(err, check.IsNil)
	dir2 := path.Join(tmpDir, "dir2")
	err = os.Mkdir(dir2, 0755)
	c.Assert(err, check.IsNil)

	// copy docker => dir
	assertSkopeoSucceeds(c, "", "copy", "docker://"+image, "dir:"+path.Join(dir1, image))
	_, err = os.Stat(path.Join(dir1, image, "manifest.json"))
	c.Assert(err, check.IsNil)

	// sync dir => docker
	assertSkopeoSucceeds(c, "", "sync", "--dest-tls-verify=false", "dir:"+dir1, localRegURL)

	// copy docker => dir
	assertSkopeoSucceeds(c, "", "copy", "--src-tls-verify=false", localRegURL+image, "dir:"+path.Join(dir2, image))
	_, err = os.Stat(path.Join(path.Join(dir2, image), "manifest.json"))
	c.Assert(err, check.IsNil)

	out := combinedOutputOfCommand(c, "diff", "-urN", dir1, dir2)
	c.Assert(out, check.Equals, "")
}

func (s *SyncSuite) TestSyncFailsWithDir2Dir(c *check.C) {
	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)

	dir1 := path.Join(tmpDir, "dir1")
	dir2 := path.Join(tmpDir, "dir2")

	// sync dir => dir is not allowed
	assertSkopeoFails(c, ".*sync from 'dir:' to 'dir:' not implemented.*", "sync", "dir:"+dir1, "dir:"+dir2)
}

func (s *SyncSuite) TestSyncFailsWithDirSourceNoImages(c *check.C) {
	const localRegURL = "docker://" + v2DockerRegistryURL + "/"

	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)

	assertSkopeoFails(c, ".*No images to sync found in SOURCE.*",
		"sync", "--dest-tls-verify=false", "dir:"+tmpDir, localRegURL)
}

func (s *SyncSuite) TestSyncFailsWithDockerSourceNoRegistry(c *check.C) {
	const regURL = "docker://google.com/namespace/imagename"

	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)

	//untagged
	assertSkopeoFails(c, ".*error pinging.*response code 404.*",
		"sync", regURL, "dir:"+tmpDir)

	//tagged
	assertSkopeoFails(c, ".*error pinging.*response code 404.*",
		"sync", regURL+":thetag", "dir:"+tmpDir)
}

func (s *SyncSuite) TestSyncFailsWithDockerSourceUnauthorized(c *check.C) {
	const repo = "docker://privateimagenamethatshouldnotbepublic"
	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)

	//untagged
	assertSkopeoFails(c, ".*Registry disallows tag list retrieval.* 401 .*",
		"sync", repo, "dir:"+tmpDir)

	//tagged
	assertSkopeoFails(c, ".*unauthorized: authentication required.*",
		"sync", repo+":thetag", "dir:"+tmpDir)
}

func (s *SyncSuite) TestSyncFailsWithDockerSourceNotExisting(c *check.C) {
	repo := fmt.Sprintf("docker://%s", path.Join(v2DockerRegistryURL, "notexistingimage"))
	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	defer os.RemoveAll(tmpDir)

	//untagged
	assertSkopeoFails(c, ".*Invalid status code returned when fetching tags list 404.*",
		"sync", "--src-tls-verify=false", repo, "dir:"+tmpDir)

	//tagged
	assertSkopeoFails(c, ".*Error determining manifest MIME type.*",
		"sync", "--src-tls-verify=false", repo+":thetag", "dir:"+tmpDir)
}

func (s *SyncSuite) TestSyncFailsWithDirSourceNotExisting(c *check.C) {
	const localRegURL = "docker://" + v2DockerRegistryURL + "/"

	// Make sure the dir does not exist!
	tmpDir, err := ioutil.TempDir("", "skopeo-sync-test")
	c.Assert(err, check.IsNil)
	err = os.RemoveAll(tmpDir)
	c.Assert(err, check.IsNil)
	_, err = os.Stat(path.Join(tmpDir))
	c.Check(os.IsNotExist(err), check.Equals, true)

	assertSkopeoFails(c, ".*no such file or directory.*",
		"sync", "--dest-tls-verify=false", "dir:"+tmpDir, localRegURL)
}
