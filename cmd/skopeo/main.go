package main

import (
	"fmt"
	"os"

	"github.com/containers/image/signature"
	"github.com/containers/storage/pkg/reexec"
	"github.com/projectatomic/skopeo/version"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// gitCommit will be the hash that the binary was built from
// and will be populated by the Makefile
var gitCommit = ""

// createApp returns a cli.App to be run or tested.
func createApp() *cli.App {
	app := cli.NewApp()
	app.EnableBashCompletion = true
	app.Name = "skopeo"
	if gitCommit != "" {
		app.Version = fmt.Sprintf("%s commit: %s", version.Version, gitCommit)
	} else {
		app.Version = version.Version
	}
	app.Usage = "Various operations with container images and container image registries"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug output",
		},
		cli.BoolTFlag{
			Name:   "tls-verify",
			Usage:  "require HTTPS and verify certificates when talking to container registries (defaults to true)",
			Hidden: true,
		},
		cli.StringFlag{
			Name:  "policy",
			Value: "",
			Usage: "Path to a trust policy file",
		},
		cli.BoolFlag{
			Name:  "insecure-policy",
			Usage: "run the tool without any policy check",
		},
		cli.StringFlag{
			Name:  "registries.d",
			Value: "",
			Usage: "use registry configuration files in `DIR` (e.g. for container signature storage)",
		},
		cli.StringFlag{
			Name:  "override-arch",
			Value: "",
			Usage: "use `ARCH` instead of the architecture of the machine for choosing images",
		},
		cli.StringFlag{
			Name:  "override-os",
			Value: "",
			Usage: "use `OS` instead of the running OS for choosing images",
		},
	}
	app.Before = func(c *cli.Context) error {
		if c.GlobalBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}
		if c.GlobalIsSet("tls-verify") {
			logrus.Warn("'--tls-verify' is deprecated, please set this on the specific subcommand")
		}
		return nil
	}
	app.Commands = []cli.Command{
		copyCmd,
		inspectCmd,
		layersCmd,
		deleteCmd,
		manifestDigestCmd,
		syncCmd,
		standaloneSignCmd,
		standaloneVerifyCmd,
		untrustedSignatureDumpCmd,
	}
	return app
}

func main() {
	if reexec.Init() {
		return
	}
	app := createApp()
	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}

// getPolicyContext handles the global "policy" flag.
func getPolicyContext(c *cli.Context) (*signature.PolicyContext, error) {
	policyPath := c.GlobalString("policy")
	var policy *signature.Policy // This could be cached across calls, if we had an application context.
	var err error
	if c.GlobalBool("insecure-policy") {
		policy = &signature.Policy{Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()}}
	} else if policyPath == "" {
		policy, err = signature.DefaultPolicy(nil)
	} else {
		policy, err = signature.NewPolicyFromFile(policyPath)
	}
	if err != nil {
		return nil, err
	}
	return signature.NewPolicyContext(policy)
}
