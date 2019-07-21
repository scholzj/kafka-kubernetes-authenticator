# Kafka Kubernetes Authenticator and Authorizer

This project provides Kafka Authenticator and Authorizer which are based on Kubernetes Service Accounts and Kubernetes RBAC.
It is using the service account tokens and the SASL OAUTHBEARER authentication mehcnaism provided by Kafka.

You can watch my demo video on YouTube:
[![Demo of a Kafka Authenticator and Authorizer based on Kubernetes ServiceAccounts and RBAC](http://img.youtube.com/vi/AF4abbVlocc/0.jpg)](http://www.youtube.com/watch?v=AF4abbVlocc "Demo of a Kafka Authenticator and Authorizer based on Kubernetes ServiceAccounts and RBAC")

## Building the project

Run `mvn clean install` to build the project.
The module subdirectories will contain the binaries which should be used.

## Authenticator

The authenticator consists of two separate parts:
* Client part which should be used with Kubernetes clients
* Server part which should be used in the Kafka brokers

### Clients

Add the `authenticator-client` module as dependency into your application using the Kafka client libraries (in Java, provided by the Apache Kafka project).
If needed, you can find the JAR in `authenticator-client/target` and the required libraries in `authenticator-client/target`.
This project is currently not available on Maven Central, so you cannot get it from there.

In your client you have to configure the use of SASL and the SASL OAUTHBEARER mechanism.
First set the `security.protocol` option to `SASL_PLAINTEXT` (or to `SASL_SSL` if you use SSL)
Next set the `sesl.mechanism` to `OAUHTBEARER` mechanism.

SASL authentication is implemented using JAAS.
So you have to configure the Kafka's OAuthBearer login module.
You can do that for example by setting the `sasl.jaas.config` to `org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required`;
Additionally you have to configure the login callback provided by this project.
In `sasl.login.callback.handler.class` set `io.strimzi.kafka.kubernetes.authenticator.KubernetesTokenLoginCallbackHandler`.

Your complete configuration might look something like this:

```java
Properties props = new Properties();
props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");

props.put("sasl.jaas.config", "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;");
props.put("security.protocol","SASL_PLAINTEXT");
props.put("sasl.mechanism","OAUTHBEARER");
props.put("sasl.login.callback.handler.class","io.strimzi.kafka.kubernetes.authenticator.KubernetesTokenLoginCallbackHandler");
```

All you need to do next is just open the connection and start sending or receiving messages.
The login callback assumes that it will run inside a Kubernetes Pod and will by default try to get the Service Account token from the default location which is the file `/var/run/secrets/kubernetes.io/serviceaccount/token` inside the Pod.
You can use the environment variable `OAUTHBEARER_TOKEN_FILE` to have the file read from a different file or the environment variable `OAUTHBEARER_TOKEN` to pass the token directly.
You can also pass the token in the `token` option in the JAAS file configuration like this:

```java
props.put("sasl.jaas.config", "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required token=XXX.YYY.ZZZ;");
```  

### Brokers

Copy the JAR from `authenticator-server/target` and the required libraries in `authenticator-server/target` into the `libs` directory of the broker.
In your server properties file, configure your listener as usually to use the SASL OAUTHBEARER mechanism.
Set the callback to the class provided by this project: 

```properties
sasl.server.callback.handler.class=io.strimzi.kafka.kubernetes.authenticator.KubernetesTokenValidatorCallbackHandler
```

Once the client connects to the broker using the OAUTHBEARER protocol it will pass the broker its Service Account token.
The broker callback will take the token and use the Kubernetes Token Review API to validate that the token is valid.
It expects the broker to run either inside a Kubernetes Pod or to have a configured Kubernets context (either in the default path, configured using the `KUBECONFIG` environment variable etc.).

An example of the principal under which will the accounts be authenticated is `system:serviceaccount:mynamespace:mysa`.

#### Required RBAC rights

The Authenticator requires the right to post the Token Review requests.
You have to give it a role similar to this:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: token-review-role
rules:
- apiGroups:
  - authentication.k8s.io
  resources:
  - tokenreviews
  verbs:
  - create
```

### Authorization

The Authorizer provided by this project is authorizing the Kafka clients based on the Kubernetes Service Accounts and Kubernetes RBAC.
It uses the `Kafka` and `KafkaTopic` resources from the [Strimzi](https://strimzi.io) project to authorize on.

Since Kafka allows only one Authorizer to exist, if will check the format of the user name.
And if it matches Kubernetes service account, it will authorize it based on RBAC.
If it doesn't, it will fall  back to the `SimpleAclAuthorizer` class shipped with Apache Kafka.
The authorizer also respects the `super.users` field to define users who will be allowed everything.

To enable the authorizer, copy the Authorizer JAR from `authorizer/target` to the `libs` directoty on your Kafka broker and configure it:

```properties
authorizer.class.name=io.strimzi.kafka.kubernetes.authorizer.KubernetesAuthorizer
``` 

The following table shows how the RBAC rights map against the Kafka ACLs.
The match here is not perfect. 
But might work for most regular consumers and producers.


	Cluster		DelegationToken		Group		Topic		TransactionalId	
Alter	Patch	Kafka	n/a	n/a	n/a	n/a	Patch	KafkaTopic	n/a	n/a
AlterConfigs	Patch	Kafka	n/a	n/a	n/a	n/a	Patch	KafkaTopic	n/a	n/a
ClusterAction	Patch	Kafka	n/a	n/a	n/a	n/a	Patch	KafkaTopic	n/a	n/a
Create	Create	Kafka	n/a	n/a	n/a	n/a	Create	KafkaTopic	n/a	n/a
Describe	List	Kafka	n/a	n/a	n/a	n/a	List	KafkaTopic	n/a	n/a
DescribeConfigs	List	Kafka	n/a	n/a	n/a	n/a	List	KafkaTopic	n/a	n/a
IdempotentWrite	update	Kafka	n/a	n/a	n/a	n/a	update	KafkaTopic	n/a	n/a
Read	get	Kafka	n/a	n/a	n/a	n/a	get	KafkaTopic	n/a	n/a
Write	update	Kafka	n/a	n/a	n/a	n/a	update	KafkaTopic	n/a	n/a
					Groups starting with the user name will be allowed				TransactionIDs starting with the user name will be allowed	


|                 | Cluster                 | Topic                        | Group | DelegationToken | TransactionalId |
| --------------- | ----------------------- | ---------------------------- | ----- | --------------- | --------------- |
| Alter           | Patch `Kafka` resource  | Patch `KafkaTopic` resource  | n/a   | n/a             | n/a             |
| AlterConfigs    | Patch `Kafka` resource  | Patch `KafkaTopic` resource  | n/a   | n/a             | n/a             |
| ClusterAction   | Patch `Kafka` resource  | Patch `KafkaTopic` resource  | n/a   | n/a             | n/a             |
| Create          | Create `Kafka` resource | Create `KafkaTopic` resource | n/a   | n/a             | n/a             |
| Describe        | List `Kafka` resource   | List `KafkaTopic` resource   | n/a   | n/a             | n/a             |
| DescribeConfigs | List `Kafka` resource   | List `KafkaTopic` resource   | n/a   | n/a             | n/a             |
| IdempotentWrite | Update `Kafka` resource | Update `KafkaTopic` resource | n/a   | n/a             | n/a             |
| Read            | Get `Kafka` resource    | Get `KafkaTopic` resource    | n/a   | n/a             | n/a             |
| Write           | Update `Kafka` resource | Update `KafkaTopic` resource | n/a   | n/a             | n/a             |

When the service account has the given right, it will be allwoed the action.
Otherwise it will be denied.

There is no resource for consumer groups or transactional IDs.
The authorizer currently handles them in a way that if they start with the ID of the user, they will be always allowed.
And example of the service account based username is `system:serviceaccount:mynamespace:mysa`.

**The authorizer is currently only experimental and does not caching of the authorization results.
Therefore it might have significant performance impact on the Kubernetes and Kafka clusters.**

#### Required RBAC rights

The Authorizer requires the RBAC rights to post Subject Access Review API calls.
You have to give the broker the rights similar to this:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: subject-access-review
rules:
- apiGroups:
  - authorization.k8s.io
  resources:
  - subjectaccessreviews
  verbs:
  - create
```

### Trying it with Strimzi

You can try this with specially modified Strimzi images.
First, create a namespace `myproject` which will be used for the demo:

```sh
kubectl create ns myproject
```

Next deploy the modified Strimzi Kafka Operator:

```sh
kubectl apply -f examples/strimzi -n myproject
```

And deploy the Kafka cluster:

```sh
kubectl apply -f examples/kafka-cluster.yaml -n myproject
```

Afterwards you can deplyo two sets of clients.
`allowed.yaml` contain simple producer and consumer which are authorized and should work properly.

```sh
kubectl apply -f examples/allowed.yaml -n myproject
```

`denied.yaml` contain two clients which will be failing.
One is configured with a token from a different cluster and should not pass authentication.
The second is using a valid service account to authenticate, but should be unauthorized.

```sh
kubectl apply -f examples/denied.yaml -n myproject
```

