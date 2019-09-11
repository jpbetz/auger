Auger
-----

Directly access data objects stored in `etcd` by `kubernetes`.

Encodes and decodes Kubernetes objects from the binary storage encoding used to
store data to `etcd`. Supports data conversion to `YAML`, `JSON` and `Protobuf`.

Automatically determines if etcd data is stored in `JSON` (`kubernetes` `1.5` and
earlier) or binary (`kubernetes` `1.6` and newer) and decodes accordingly.

Why?
----

In earlier versions of `kubernetes`, data written to `etcd` was stored as `JSON`
and could easily be inspected or manipulated using standard tools such as
`etcdctl`. In `kubernetes` `1.6+`, for efficiency reasons, much of the data is
now stored in a binary storage representation, and is non-trivial to decode-- it
contains a enveloped payload that must be unpacked, type resolved and decoded.

This tool provides `kubernetes` developers and cluster operators with simple way
to access the binary storage data via `YAML` and `JSON`.

Installation
------------

Check out and build:

```sh
git clone https://github.com/jpbetz/auger
cd auger
make release
```

Run:


```sh
build/auger -h
```

Use cases
---------

### Access data via etcdctl

A kubernetes developer or cluster operator needs to inspect the data actually
stored to etcd for a particular kubernetes object.

E.g., decode a pod from etcd v3, where `<pod-name>` is the name of one of your pods:

``` sh
ETCDCTL_API=3 etcdctl get /registry/pods/default/<pod-name> | auger decode
> apiVersion: v1
> kind: Pod
> metadata:
>   annotations: ...
>   creationTimestamp: 2017-06-27T16:35:34Z
> ...
```

### Modify data via etcdctl

A kubernetes developer or etcd developer needs to modify state of an object stored in etcd.

E.g. Write an updated pod to etcd v3:

``` sh
cat updated-pod.yaml | auger encode | ETCDCTL_API=3 etcdctl put /registry/pods/default/<pod-name>
```

### Access data directly from db file

A cluster operator, kubernetes developer or etcd developer is needs to inspect
etcd data without starting etcd. In extreme cases, it may not be possible to
start etcd and inspecting the data may help a etcd developer understand what
state it is in.

E.g. find an etcd value by it's key and extract it from a boltdb file:

``` sh
auger extract -f <boltdb-file> -k /registry/pods/default/<pod-name>
> apiVersion: v1
> kind: Pod
> metadata:
>   annotations: ...
>   creationTimestamp: 2017-06-27T16:35:34Z
> ...
```

Query for specific data directly from a db file:

``` sh
auger extract -f <boltdb-file> --template="{{.Value.kind}} {{.Value.metadata.name}}" --filter=".Value.metadata.namespace=default"
> Endpoints kubernetes
> Service kubernetes
> ...
```

### Consistency and corruption checking

First get a checksum and latest revsion from one of the members:

``` sh
auger checksum -f <member-1-boltdb-file>
> checksum: 1282050701
> revision: 7
```

Then compare it with the other members:

``` sh
auger checksum -f <member-2-boltdb-file> -r 7
> checksum: 1282050701
> revision: 7

auger checksum -f <member-3-boltdb-file> -r 7
> checksum: 8482350767
> revision: 7
# Oh noes! The checksum should have been the same!
```

TODO
----

- [ ] Warn if attempting to read data written by a different version of kubernetes
- [ ] Add detection of unrecognized fields in stored data, which would suggest
      data was written with newer version of proto schema
- [ ] Build and publish releases for all recent kubernetes versions (1.6+)
