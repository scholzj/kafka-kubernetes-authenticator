package io.strimzi.kafka.kubernetes.authorizer;

import io.fabric8.kubernetes.client.DefaultKubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.base.OperationSupport;
import kafka.network.RequestChannel;
import kafka.security.auth.Acl;
import kafka.security.auth.Authorizer;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import kafka.security.auth.ResourceType;
import kafka.security.auth.SimpleAclAuthorizer;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class KubernetesAuthorizer implements Authorizer {
    private static final Logger log = LoggerFactory.getLogger(KubernetesAuthorizer.class);

    private static String STRIMZI_API_GROUP = "kafka.strimzi.io";
    private static String STRIMZI_KAFKA_TOPICS = "kafkatopics";
    private static String STRIMZI_KAFKAS = "kafkas";

    private static String KUBERNETES_GET = "get";
    private static String KUBERNETES_UPDATE = "update";
    private static String KUBERNETES_CREATE = "create";
    private static String KUBERNETES_LIST = "list";
    private static String KUBERNETES_PATCH = "patch";

    private static final Pattern SERVICE_ACCOUNT = Pattern.compile("^system:serviceaccount:([a-z0-9.-]+:)([a-z0-9.-]+)$");

    private boolean isConfigured = false;

    private SimpleAclAuthorizer simpleAuthorizer;
    private List<String> superUsers;
    private KubernetesClient client;
    private OkHttpClient httpClient;
    private String namespace;

    @Override
    public boolean authorize(RequestChannel.Session session, Operation operation, Resource resource) {
        if (!isConfigured)  {
            throw new RuntimeException("Kubernetes Authorizer is not configured yet!");
        }

        KafkaPrincipal principal = session.principal();

        if (KafkaPrincipal.USER_TYPE.equals(principal.getPrincipalType()) && SERVICE_ACCOUNT.matcher(principal.getName()).matches())    {
            String sa = principal.getName();

            if (log.isTraceEnabled()) {
                log.trace("Authorizing Kubernetes service account {}", sa);
            }

            if (superUsers.contains(sa))    {
                log.debug("{} is supper user and can do whatever it wants", sa);
                return true;
            }

            ResourceType type = resource.resourceType();
            String resourceName = resource.name();
            AclOperation op = operation.toJava();

            String reviewRequestGroup = "";
            String reviewRequestResource = "";
            String reviewRequestVerb = "";
            String reviewRequestName = "";

            switch (type.toJava())   {
                case TOPIC:
                    reviewRequestGroup = STRIMZI_API_GROUP;
                    reviewRequestResource = STRIMZI_KAFKA_TOPICS;
                    reviewRequestName = resourceName;

                    switch (op) {
                        case ALTER:
                        case ALTER_CONFIGS:
                        case CLUSTER_ACTION:
                            reviewRequestVerb = KUBERNETES_PATCH;
                            break;

                        case CREATE:
                            reviewRequestVerb = KUBERNETES_CREATE;
                            break;

                        case DESCRIBE:
                        case DESCRIBE_CONFIGS:
                            reviewRequestVerb = KUBERNETES_LIST;
                            break;

                        case IDEMPOTENT_WRITE:
                        case WRITE:
                            reviewRequestVerb = KUBERNETES_UPDATE;
                            break;

                        case READ:
                            reviewRequestVerb = KUBERNETES_GET;
                            break;
                    }

                    break;

                case CLUSTER:
                    reviewRequestGroup = STRIMZI_API_GROUP;
                    reviewRequestResource = STRIMZI_KAFKAS;
                    reviewRequestName = resourceName;

                    switch (op) {
                        case ALTER:
                        case ALTER_CONFIGS:
                        case CLUSTER_ACTION:
                            reviewRequestVerb = KUBERNETES_PATCH;
                            break;

                        case CREATE:
                            reviewRequestVerb = KUBERNETES_CREATE;
                            break;

                        case DESCRIBE:
                        case DESCRIBE_CONFIGS:
                            reviewRequestVerb = KUBERNETES_LIST;
                            break;

                        case IDEMPOTENT_WRITE:
                        case WRITE:
                            reviewRequestVerb = KUBERNETES_UPDATE;
                            break;

                        case READ:
                            reviewRequestVerb = KUBERNETES_GET;
                            break;
                    }

                    break;

                case GROUP:
                case TRANSACTIONAL_ID:
                    if (resourceName != null && resourceName.startsWith(sa)) {
                        return true;
                    } else {
                        return false;
                    }

                case DELEGATION_TOKEN:
                    return false;
            }

            try {
                boolean result = false;

                String requestBodyJson = SubjectAccessReviewUtils.getSubjectAccessReviewRequest(namespace, sa, reviewRequestGroup, reviewRequestResource, reviewRequestVerb, reviewRequestName);
                RequestBody body = RequestBody.create(OperationSupport.JSON, requestBodyJson);
                String requestUrl = client.getMasterUrl().toString() + SubjectAccessReviewUtils.getUrlPath();

                if (log.isTraceEnabled()) {
                    log.trace("Requesting SubjectAccessReview from {}: {}", requestBodyJson, requestUrl);
                }

                Response reviewResult = httpClient.newCall(new Request.Builder().post(body).url(requestUrl).build()).execute();
                ResponseBody reviewResultBody = reviewResult.body();

                if (reviewResult.code() == 201 && reviewResultBody != null) {
                    String reviewResultJson = reviewResultBody.string();

                    if (log.isTraceEnabled()) {
                        log.trace("Received SubjectAccessReview response: {}", reviewResultJson);
                    }

                    if (SubjectAccessReviewUtils.isAllowed(reviewResultJson)) {
                        log.debug("User {} is allowed operation {} on resource {}", sa, operation, resource);
                        result = true;
                    } else {
                        log.info("User {} is denied operation {} on resource {}", sa, operation, resource);
                        result = false;
                    }
                } else {
                    if (reviewResultBody != null && log.isTraceEnabled()) {
                        String reviewResultJson = reviewResultBody.string();
                        log.trace("Received SubjectAccessReview response: {}", reviewResultJson);
                    }

                    log.info("Failed to review the access. SubjectAccessReview returned HTTP {}.", reviewResult.code());
                    result = false;
                }

                reviewResult.close();
                return result;
            }
            catch (IOException e)   {
                log.info("Failed to process access review", e);
                return false;
            }
        } else {
            log.info("Authorizing regular user {}:{}. Will be passed to SimpleAclAuthorizer.", principal.getPrincipalType(), principal.getName());
            return simpleAuthorizer.authorize(session, operation, resource);
        }
    }

    @Override
    public void addAcls(scala.collection.immutable.Set<Acl> acls, Resource resource) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean removeAcls(scala.collection.immutable.Set<Acl> acls, Resource resource) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean removeAcls(Resource resource) {
        throw new UnsupportedOperationException();
    }

    @Override
    public scala.collection.immutable.Set<Acl> getAcls(Resource resource) {
        throw new UnsupportedOperationException();
    }

    @Override
    public scala.collection.immutable.Map<Resource, scala.collection.immutable.Set<Acl>> getAcls(KafkaPrincipal principal) {
        throw new UnsupportedOperationException();
    }

    @Override
    public scala.collection.immutable.Map<Resource, scala.collection.immutable.Set<Acl>> getAcls() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void close() {
        simpleAuthorizer.close();
    }

    @Override
    public void configure(Map<String, ?> configs) {
        // Craate Kubernetes client
        client = new DefaultKubernetesClient();
        namespace = client.getConfiguration().getNamespace();
        httpClient = client.adapt(OkHttpClient.class);

        // configure the
        simpleAuthorizer = new SimpleAclAuthorizer();
        simpleAuthorizer.configure(configs);

        String superUsersString = ((String) configs.get("super.users"));
        superUsers = Arrays.asList(superUsersString.split(";"));

        isConfigured = true;
    }
}
