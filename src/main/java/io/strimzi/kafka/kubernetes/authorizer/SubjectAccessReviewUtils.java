package io.strimzi.kafka.kubernetes.authorizer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class SubjectAccessReviewUtils {
    public static String getUrlPath()   {
        return "apis/" + SubjectAccessReviewUtils.getApiVersion() + "/subjectaccessreviews";
    }

    public static String getApiVersion() {
        return "authorization.k8s.io/v1";
    }

    public static String getSubjectAccessReviewRequest(String namespace, String sa, String group, String resource, String verb, String name)    {
        return "{\n" +
                "  \"apiVersion\": \"" + getApiVersion() + "\",\n" +
                "  \"kind\": \"SubjectAccessReview\",\n" +
                "  \"spec\": {\n" +
                "    \"user\": \"" + sa + "\",\n" +
                "    \"resourceAttributes\": {\n" +
                "      \"group\": \"" + group + "\",\n" +
                "      \"resource\": \"" + resource + "\",\n" +
                "      \"verb\": \"" + verb + "\",\n" +
                "      \"name\": \"" + name + "\",\n" +
                "      \"namespace\": \"" + namespace + "\"\n" +
                "    }\n" +
                "  }\n" +
                "}";
    }

    public static boolean isAllowed(String reviewResult) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode json = mapper.readTree(reviewResult);

        if (json.get("status") != null)    {
            JsonNode status = json.get("status");

            if (status.get("allowed") != null)  {
                String allowed = status.get("allowed").asText();
                return Boolean.parseBoolean(allowed);
            }
        }

        return false;
    }
}
