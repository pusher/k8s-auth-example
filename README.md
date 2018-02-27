# Kubernetes Authentication Example
This code is provided verbatim as an example of how to connect to an OIDC
provider and authenticate users before configuring their `kubeconfig`.

At [Pusher](https://pusher.com), we distribute a copy of this app to our engineers
which sources all required information from Vault and configures their cluster
contexts as well.

You may also wish to build your own version of this app, sourcing it's
configuration automatically, to improve your user-experience.

## Attribution
This project started life as the [Dex example app](https://github.com/coreos/dex/tree/master/cmd/example-app).

## Usage
You will need to configure an OIDC application with your Identity Provider.

The redirect URI should be `http://127.0.0.1:5555/callback` and you will need to
make a note of the issuer URL and the client secret that you set/are given.

We use Dex so I've included an example Dex config snippet below:
```
staticClients:
- id: kubernetes
  redirectURIs:
  - 'http://127.0.0.1:5555/callback'
  name: 'Kubernetes API'
  secret: c3VwZXJzZWNyZXRzdHJpbmcK
```

With this configuration, and a Dex instance running at https://auth.exmaple.com/dex,
the following command will initiate the login flow:
```
./k8s-auth-example --client-secret c3VwZXJzZWNyZXRzdHJpbmcK --client-id kubernetes --issuer https://auth.exmaple.com/dex
```

## Building
The application is written in Go using [`dep`](https://github.com/golang/dep)
as the package manager. The following will get you your first build:

```
go get git@github.com/pusher/k8s-auth-example
cd $GOPATH/src/github.com/pusher/k8s-auth-example
dep ensure
go build -o k8s-auth
```

## Communication

* Found a bug? Please open an issue.
* Have a feature request. Please open an issue.
* If you want to contribute, please submit a pull request

## Contributing
Please see our [Contributing](CONTRIBUTING.md) guidelines.

## License
This project is licensed under Apache 2.0 and a copy of the license is available [here](LICENSE).
