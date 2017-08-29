kvstore-tool
------------
Decodes kubernetes objects from the binary storage and JSON encodings persisted to etcd. Outputs to YAML, JSON, or Protobuf.

Installation
------------

Requirements:

- [glide](https://github.com/Masterminds/glide)
- go 1.8.3+

``` sh
$ go get -d github.com/jpbetz/kvstore-tool
$ cd $GOPATH/src/github.com/jpbetz/kvstore-tool
$ glide install --strip-vendor
$ go install
```

Example Usage
-------------

Decode a pod from etcd v3, where `<pod-name>` is the name of one of your pods:

``` sh
ETCDCTL_API=3 etcdctl get /registry/pods/default/<pod-name> | kvstore-tool decode
> apiVersion: v1
> kind: Pod
> metadata:
>   annotations: ...
>   creationTimestamp: 2017-06-27T16:35:34Z
> ...
```

Find an etcd value by it's key and extract it from a boltdb file:

``` sh
kvstore-tool extract -f <boltdb-file> -k /registry/pods/default/<pod-name>
```

TODO
----

- [ ] Add a docker based build so we can simplify the instructions and
      minimize the number of environment based build problems
- [ ] Add write support - ability to encode data back to storage format
- [ ] Add detection of unrecognized fields in stored data, which would suggest
      data was written with newer version of proto schema
- [ ] Add ability to decode using proto files from a provided kubernetes project directory
- [ ] Add auto-detection of data stored as json, decode appropriately
