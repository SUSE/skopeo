% skopeo-sync(1)

## NAME
skopeo\-sync - Copy images from one or more repositories to a user specified destination.

## SYNOPSIS
**skopeo sync** [**--source-yaml**] _source_ _destination_

## DESCRIPTION
Copy images from one or more repositories to a user specified destination.

Useful to keep in sync with a local container registry mirror. It can also be used to populate registries running inside of air-gapped environments.

_source_ can be:
 - a repository hosted on a container registry (eg: docker://registry.example.com/busybox)
 - a local directory (eg: dir:/media/usb/).
 - (when **--source-yaml** is specified) a YAML file with a list of source images from different container registries.

When the source location is a container repository and no tags are specified,  **skopeo sync** will copy all the tags associated to the source image.

_destination_ can be either a container registry (eg: docker://my-registry.local.lan) or a local directory (eg: dir:/media/usb).

When _destination_ is a local directory, one directory per 'image:tag' will be created.

## OPTIONS

**--authfile** _path_

Path of the authentication file. Default is ${XDG_RUNTIME\_DIR}/containers/auth.json, which is set using `podman login`.
If the authorization state is not found there, $HOME/.docker/config.json is checked, which is set using `docker login`.

**--remove-signatures** do not copy signatures, if any, from _source-image_. Necessary when copying a signed image to a destination which does not support signatures.

**--sign-by=**_key-id_ add a signature using that key ID for an image name corresponding to _destination-image_

**--source-yaml** Interpret _source_ as a YAML file with a list of images from different container registries

**--src-creds** _username[:password]_ for accessing the source registry

**--dest-compress** _bool-value_ Compress tarball image layers when saving to directory using the 'dir' transport. (default is same compression type as source)

**--dest-creds** _username[:password]_ for accessing the destination registry

**--src-cert-dir** _path_ Use certificates at _path_ (*.crt, *.cert, *.key) to connect to the source registry or daemon

**--src-tls-verify** _bool-value_ Require HTTPS and verify certificates when talking to container source registry or daemon (defaults to true)

**--dest-cert-dir** _path_ Use certificates at _path_ (*.crt, *.cert, *.key) to connect to the destination registry or daemon

**--dest-tls-verify** _bool-value_ Require HTTPS and verify certificates when talking to container destination registry or daemon (defaults to true)

## EXAMPLES

Content of a YAML file to be used with **--source-yaml**:

```yaml
docker.io:
    images:
        busybox: []
        redis:
            - "1.0"
            - "2.0"
    credentials:
        username: john
        password: this is a secret
    tls-verify: true
    cert-dir: /home/john/certs
quay.io:
    images:
        coreos/etcd:
            - latest
```

## SEE ALSO
skopeo(1), podman-login(1), docker-login(1)

## AUTHORS

Antonio Murdaca <runcom@redhat.com>, Miloslav Trmac <mitr@redhat.com>, Jhon Honce <jhonce@redhat.com>

