package io.micronaut.supabase.storage;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Inject;
import jakarta.validation.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises every route of {@link SupabaseStorageClient} against a real Supabase Storage API server started
 * with Testcontainers. Each test creates its own buckets so tests do not depend on each other. Writes
 * authenticate with a legacy service-role JWT, which bypasses Row Level Security; the anon JWT and the public
 * routes verify what an anonymous caller may see.
 */
@Testcontainers(disabledWithoutDocker = true)
@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SupabaseStorageClientTest implements TestPropertyProvider {
    private static final String TEXT_PLAIN = "text/plain";
    private static final byte[] HELLO = "hello world".getBytes(StandardCharsets.UTF_8);

    @Inject
    SupabaseStorageClient client;

    private final String service = SupabaseStorage.serviceAuthorization();
    private final String anon = SupabaseStorage.anonAuthorization();

    @Override
    public @NonNull Map<String, String> getProperties() {
        return SupabaseStorage.getProperties();
    }

    // ------------------------------------------------------------------ health

    @Test
    void healthReportsHealthyForAnyValidToken() {
        assertEquals(Boolean.TRUE, client.health(service).body().get("healthy"));
        assertEquals(Boolean.TRUE, client.health(anon).body().get("healthy"));
    }

    @Test
    void healthRejectsAnInvalidToken() {
        assertError(HttpStatus.BAD_REQUEST, "AccessDenied", () -> client.health("Bearer not-a-jwt"));
    }

    // ------------------------------------------------------------------ buckets

    @Test
    void bucketLifecycleCreateGetListUpdateDelete() {
        String name = uniqueBucket("crud");

        HttpResponse<CreateBucketResponse> created = client.createBucket(service,
            new CreateBucketRequest(name, null, true, null, null, 1048576, List.of(TEXT_PLAIN, "image/png")));
        assertEquals(HttpStatus.OK, created.getStatus());
        assertEquals(name, created.body().name());

        BucketSchema bucket = client.getBucket(service, name).body();
        assertEquals(name, bucket.id());
        assertEquals(name, bucket.name());
        assertEquals(Boolean.TRUE, bucket.isPublic());
        assertEquals(1048576L, bucket.fileSizeLimit());
        assertEquals(List.of(TEXT_PLAIN, "image/png"), bucket.allowedMimeTypes());
        assertEquals("DISABLED", bucket.versioningStatus());
        assertNotNull(bucket.createdAt());

        List<BucketSchema> listed = client.listBuckets(service, 100, 0, "name", "asc", name).body();
        assertEquals(1, listed.size());
        assertEquals("STANDARD", listed.getFirst().type());

        assertEquals("Successfully updated", client.updateBucket(service, name,
            new UpdateBucketRequest(false, "2MB", List.of("image/png"), null)).body().message());
        BucketSchema updated = client.getBucket(service, name).body();
        assertEquals(Boolean.FALSE, updated.isPublic());
        assertEquals(2_000_000L, updated.fileSizeLimit(), "2MB is decimal");
        assertEquals(List.of("image/png"), updated.allowedMimeTypes());

        assertEquals("Successfully deleted", client.deleteBucket(service, name).body().message());
        assertError(HttpStatus.BAD_REQUEST, "NoSuchBucket", () -> client.getBucket(service, name));
    }

    @Test
    void listBucketsWithoutFiltersReturnsEveryBucket() {
        String first = uniqueBucket("list-a");
        String second = uniqueBucket("list-b");
        client.createBucket(service, new CreateBucketRequest(first, null, null, null, null, null, null));
        client.createBucket(service, new CreateBucketRequest(second, null, null, null, null, null, null));

        List<String> names = client.listBuckets(service, null, null, null, null, null).body().stream().map(BucketSchema::name).toList();

        assertTrue(names.contains(first));
        assertTrue(names.contains(second));
    }

    @Test
    void emptyBucketQueuesTheDeletionOfItsObjects() {
        String name = createBucket("empty", false);
        client.uploadObject(service, name, "a.txt", TEXT_PLAIN, null, null, null, HELLO);

        MessageResponse response = client.emptyBucket(service, name).body();

        assertNotNull(response.message());
        assertTrue(response.message().startsWith("Empty bucket has been queued"), response.message());
    }

    @Test
    void anonCannotCreateBucketsAndSeesNone() {
        String name = createBucket("anon", true);

        assertError(HttpStatus.BAD_REQUEST, "AccessDenied",
            () -> client.createBucket(anon, new CreateBucketRequest(uniqueBucket("anon-create"), null, null, null, null, null, null)));
        assertEquals(List.of(), client.listBuckets(anon, null, null, null, null, name).body(), "no policy grants anon access to storage.buckets");
    }

    @Test
    void lifecycleConfigurationOfAVersionedBucket() {
        String name = uniqueBucket("lifecycle");
        client.createBucket(service, new CreateBucketRequest(name, null, false, null, "ENABLED", null, null));
        assertEquals("ENABLED", client.getBucket(service, name).body().versioningStatus());

        assertError(HttpStatus.BAD_REQUEST, "NoSuchLifecycleConfiguration", () -> client.getBucketLifecycle(service, name));

        LifecycleConfiguration configuration = new LifecycleConfiguration(List.of(
            new LifecycleConfiguration.Rule("expire-old", "Enabled", Map.of(), new LifecycleConfiguration.NoncurrentVersionExpiration(30, 2))));
        LifecycleConfiguration stored = client.putBucketLifecycle(service, name, configuration).body();
        assertEquals(configuration, stored);
        assertEquals(configuration, client.getBucketLifecycle(service, name).body());

        LifecycleConfiguration prefixed = new LifecycleConfiguration(List.of(
            new LifecycleConfiguration.Rule(null, "Enabled", Map.of("prefix", "logs/"), new LifecycleConfiguration.NoncurrentVersionExpiration(30, null))));
        assertError(HttpStatus.BAD_REQUEST, "InvalidParameter", () -> client.putBucketLifecycle(service, name, prefixed));

        assertEquals("Successfully deleted", client.deleteBucketLifecycle(service, name).body().message());
        assertError(HttpStatus.BAD_REQUEST, "NoSuchLifecycleConfiguration", () -> client.getBucketLifecycle(service, name));
    }

    // ------------------------------------------------------------------ objects

    @Test
    void uploadDownloadInfoAndDeleteAnObject() {
        String bucket = createBucket("objects", false);
        String metadata = Base64.getEncoder().encodeToString("{\"owner\":\"alice\"}".getBytes(StandardCharsets.UTF_8));

        UploadObjectResponse uploaded = client.uploadObject(service, bucket, "folder/hello.txt", TEXT_PLAIN, "max-age=60", null, metadata, HELLO).body();
        assertEquals(bucket + "/folder/hello.txt", uploaded.key());
        assertNotNull(uploaded.id());

        HttpResponse<byte[]> download = client.getObject(service, bucket, "folder/hello.txt", null, null);
        assertEquals(HttpStatus.OK, download.getStatus());
        assertArrayEquals(HELLO, download.body());
        assertEquals(TEXT_PLAIN, download.getHeaders().get(HttpHeaders.CONTENT_TYPE));
        assertEquals("max-age=60", download.getHeaders().get(HttpHeaders.CACHE_CONTROL));
        assertNotNull(download.getHeaders().get(HttpHeaders.ETAG));

        HttpResponse<byte[]> attachment = client.getAuthenticatedObject(service, bucket, "folder/hello.txt", "renamed.txt", null);
        assertArrayEquals(HELLO, attachment.body());
        assertTrue(attachment.getHeaders().get(HttpHeaders.CONTENT_DISPOSITION).contains("filename=renamed.txt"));

        ObjectInfoSchema info = client.getObjectInfo(service, bucket, "folder/hello.txt", null).body();
        assertEquals(uploaded.id(), info.id());
        assertEquals("folder/hello.txt", info.name());
        assertEquals(bucket, info.bucketId());
        assertEquals((long) HELLO.length, info.size());
        assertEquals(TEXT_PLAIN, info.contentType());
        assertEquals("max-age=60", info.cacheControl());
        assertEquals(Map.of("owner", "alice"), info.metadata());
        assertEquals(Boolean.FALSE, info.isVersioned());
        assertEquals(info, client.getAuthenticatedObjectInfo(service, bucket, "folder/hello.txt", null).body());
        assertEquals(info, client.getObjectInfo(service, bucket, "folder/hello.txt", info.version()).body());

        assertEquals("Successfully deleted", client.deleteObject(service, bucket, "folder/hello.txt", null).body().message());
        assertError(HttpStatus.BAD_REQUEST, "NoSuchKey", () -> client.deleteObject(service, bucket, "folder/hello.txt", null));
        assertError(HttpStatus.BAD_REQUEST, "NoSuchKey", () -> client.getObject(service, bucket, "folder/hello.txt", null, null));
    }

    @Test
    void uploadingAnExistingKeyNeedsUpsert() {
        String bucket = createBucket("upsert", false);
        client.uploadObject(service, bucket, "hello.txt", TEXT_PLAIN, null, null, null, HELLO);

        assertError(HttpStatus.BAD_REQUEST, "KeyAlreadyExists",
            () -> client.uploadObject(service, bucket, "hello.txt", TEXT_PLAIN, null, null, null, HELLO));

        byte[] replacement = "hello upsert".getBytes(StandardCharsets.UTF_8);
        client.uploadObject(service, bucket, "hello.txt", TEXT_PLAIN, null, true, null, replacement);
        assertArrayEquals(replacement, client.getObject(service, bucket, "hello.txt", null, null).body());

        byte[] updated = "hello update".getBytes(StandardCharsets.UTF_8);
        assertEquals(bucket + "/hello.txt", client.updateObject(service, bucket, "hello.txt", TEXT_PLAIN, "no-cache", null, updated).body().key());
        assertArrayEquals(updated, client.getObject(service, bucket, "hello.txt", null, null).body());
    }

    @Test
    void uploadsAreCheckedAgainstTheBucketMimeTypes() {
        String bucket = uniqueBucket("mime");
        client.createBucket(service, new CreateBucketRequest(bucket, null, false, null, null, null, List.of("image/png")));

        assertError(HttpStatus.BAD_REQUEST, "InvalidMimeType",
            () -> client.uploadObject(service, bucket, "hello.txt", TEXT_PLAIN, null, null, null, HELLO));
    }

    @Test
    void versionedBucketKeepsNoncurrentVersions() {
        String bucket = uniqueBucket("versions");
        client.createBucket(service, new CreateBucketRequest(bucket, null, false, null, "ENABLED", null, null));
        client.uploadObject(service, bucket, "v.txt", TEXT_PLAIN, null, null, null, "v1".getBytes(StandardCharsets.UTF_8));
        String firstVersion = client.getObjectInfo(service, bucket, "v.txt", null).body().version();
        client.uploadObject(service, bucket, "v.txt", TEXT_PLAIN, null, true, null, "v2".getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("v2".getBytes(StandardCharsets.UTF_8), client.getObject(service, bucket, "v.txt", null, null).body());
        assertArrayEquals("v1".getBytes(StandardCharsets.UTF_8), client.getObject(service, bucket, "v.txt", null, firstVersion).body());
        List<ObjectSchema> versions = client.listObjects(service, bucket, new ListObjectsRequest("", null, null, null, null, null, "include", null)).body();
        assertEquals(2, versions.size());
        assertTrue(versions.stream().allMatch(version -> Boolean.TRUE.equals(version.isVersioned())));
        assertEquals(1, versions.stream().filter(version -> version.archivedAt() != null).count());

        assertEquals("Successfully deleted", client.deleteObject(service, bucket, "v.txt", firstVersion).body().message());
        assertError(HttpStatus.BAD_REQUEST, "NoSuchKey", () -> client.getObject(service, bucket, "v.txt", null, firstVersion));
        assertArrayEquals("v2".getBytes(StandardCharsets.UTF_8), client.getObject(service, bucket, "v.txt", null, null).body());
    }

    @Test
    void publicRoutesServeOnlyPublicBuckets() {
        String publicBucket = createBucket("public", true);
        String privateBucket = createBucket("private", false);
        client.uploadObject(service, publicBucket, "a/hello.txt", TEXT_PLAIN, null, null, null, HELLO);
        client.uploadObject(service, privateBucket, "a/hello.txt", TEXT_PLAIN, null, null, null, HELLO);

        HttpResponse<byte[]> download = client.getPublicObject(publicBucket, "a/hello.txt", "", null);
        assertArrayEquals(HELLO, download.body());
        assertTrue(download.getHeaders().get(HttpHeaders.CONTENT_DISPOSITION).startsWith("attachment"));
        assertEquals("a/hello.txt", client.getPublicObjectInfo(publicBucket, "a/hello.txt", null).body().name());

        assertError(HttpStatus.BAD_REQUEST, "NoSuchBucket", () -> client.getPublicObject(privateBucket, "a/hello.txt", null, null));
        assertError(HttpStatus.BAD_REQUEST, "NoSuchBucket", () -> client.getPublicObjectInfo(privateBucket, "a/hello.txt", null));
        assertError(HttpStatus.BAD_REQUEST, "NoSuchKey", () -> client.getAuthenticatedObject(anon, privateBucket, "a/hello.txt", null, null));
        assertError(HttpStatus.BAD_REQUEST, "NoSuchKey", () -> client.getPublicObject(publicBucket, "a/missing.txt", null, null));
    }

    @Test
    void listObjectsWithOffsetAndCursorPagination() {
        String bucket = createBucket("list", false);
        client.uploadObject(service, bucket, "docs/a.txt", TEXT_PLAIN, null, null, null, HELLO);
        client.uploadObject(service, bucket, "docs/b.txt", TEXT_PLAIN, null, null, null, HELLO);
        client.uploadObject(service, bucket, "images/c.txt", TEXT_PLAIN, null, null, null, HELLO);

        List<ObjectSchema> docs = client.listObjects(service, bucket,
            new ListObjectsRequest("docs", null, 10, 0, new ListObjectsRequest.SortBy("name", "desc"), null, null, null)).body();
        assertEquals(List.of("b.txt", "a.txt"), docs.stream().map(ObjectSchema::name).toList());
        assertEquals(11, docs.getFirst().metadata().get("size"));
        assertEquals(TEXT_PLAIN, docs.getFirst().metadata().get("mimetype"));

        List<ObjectSchema> searched = client.listObjects(service, bucket,
            new ListObjectsRequest("docs", null, null, null, null, "b", null, null)).body();
        assertEquals(List.of("b.txt"), searched.stream().map(ObjectSchema::name).toList());

        List<ObjectSchema> root = client.listObjects(service, bucket, new ListObjectsRequest("", null, null, null, null, null, null, null)).body();
        assertEquals(List.of("docs", "images"), root.stream().map(ObjectSchema::name).sorted().toList());
        assertTrue(root.stream().allMatch(folder -> folder.id() == null));

        ListObjectsV2Response folders = client.listObjectsV2(service, bucket,
            new ListObjectsV2Request("", null, 10, null, true, null, null, null)).body();
        assertEquals(List.of("docs/", "images/"), folders.folders().stream().map(ObjectSchema::name).sorted().toList());
        assertEquals(List.of(), folders.objects());
        assertFalse(folders.hasNext());

        ListObjectsV2Response firstPage = client.listObjectsV2(service, bucket,
            new ListObjectsV2Request("docs/", null, 1, null, null, new ListObjectsRequest.SortBy("name", "asc"), null, null)).body();
        assertEquals(List.of("docs/a.txt"), firstPage.objects().stream().map(ObjectSchema::name).toList());
        assertTrue(firstPage.hasNext());
        assertNotNull(firstPage.nextCursor());

        ListObjectsV2Response secondPage = client.listObjectsV2(service, bucket,
            new ListObjectsV2Request("docs/", null, 1, firstPage.nextCursor(), null, new ListObjectsRequest.SortBy("name", "asc"), null, null)).body();
        assertEquals(List.of("docs/b.txt"), secondPage.objects().stream().map(ObjectSchema::name).toList());
        assertFalse(secondPage.hasNext());
    }

    @Test
    void copyMoveAndBulkDeleteObjects() {
        String bucket = createBucket("copy", false);
        String archive = createBucket("archive", false);
        String metadata = Base64.getEncoder().encodeToString("{\"owner\":\"alice\"}".getBytes(StandardCharsets.UTF_8));
        client.uploadObject(service, bucket, "folder/hello.txt", TEXT_PLAIN, null, null, metadata, HELLO);

        CopyObjectResponse copy = client.copyObject(service,
            new CopyObjectRequest(bucket, "folder/hello.txt", null, archive, "2026/hello.txt", null, true)).body();
        assertEquals(archive + "/2026/hello.txt", copy.key());
        assertEquals(copy.objectId(), copy.id());
        assertEquals("2026/hello.txt", copy.name());
        assertEquals(archive, copy.bucketId());
        assertEquals(Map.of("owner", "alice"), copy.userMetadata());
        assertEquals(11, copy.metadata().get("size"));
        assertArrayEquals(HELLO, client.getObject(service, archive, "2026/hello.txt", null, null).body());

        assertEquals("Successfully moved", client.moveObject(service,
            new MoveObjectRequest(bucket, "folder/hello.txt", null, null, "moved/hello.txt")).body().message());
        assertError(HttpStatus.BAD_REQUEST, "NoSuchKey", () -> client.getObject(service, bucket, "folder/hello.txt", null, null));
        assertArrayEquals(HELLO, client.getObject(service, bucket, "moved/hello.txt", null, null).body());

        List<ObjectSchema> deleted = client.deleteObjects(service, bucket, new DeleteObjectsRequest(List.of("moved/hello.txt", "missing.txt"))).body();
        assertEquals(List.of("moved/hello.txt"), deleted.stream().map(ObjectSchema::name).toList());
        assertEquals(bucket, deleted.getFirst().bucketId());
        assertEquals(List.of(), client.deleteObjects(service, bucket, new DeleteObjectsRequest(List.of("missing.txt"))).body());
    }

    // ------------------------------------------------------------------ signed URLs

    @Test
    void signedUrlsDownloadWithoutCredentials() {
        String bucket = createBucket("sign", false);
        client.uploadObject(service, bucket, "folder/hello.txt", TEXT_PLAIN, null, null, null, HELLO);

        String signedUrl = client.signObject(service, bucket, "folder/hello.txt", new SignObjectRequest(60, null, null)).body().signedUrl();
        assertTrue(signedUrl.startsWith("/object/sign/" + bucket + "/folder/hello.txt?token="), signedUrl);
        String token = signedUrl.substring(signedUrl.indexOf("token=") + "token=".length());

        HttpResponse<byte[]> download = client.getSignedObject(bucket, "folder/hello.txt", token, null);
        assertArrayEquals(HELLO, download.body());
        assertNull(download.getHeaders().get(HttpHeaders.CONTENT_DISPOSITION));
        HttpResponse<byte[]> attachment = client.getSignedObject(bucket, "folder/hello.txt", token, "renamed.txt");
        assertTrue(attachment.getHeaders().get(HttpHeaders.CONTENT_DISPOSITION).contains("filename=renamed.txt"));

        assertError(HttpStatus.BAD_REQUEST, "InvalidJWT", () -> client.getSignedObject(bucket, "folder/hello.txt", "not-a-token", null));

        List<SignedUrlEntry> entries = client.signObjects(service, bucket, new SignObjectsRequest(60, List.of("folder/hello.txt", "missing.txt"))).body();
        assertEquals(2, entries.size());
        assertNull(entries.get(0).error());
        assertEquals("folder/hello.txt", entries.get(0).path());
        assertTrue(entries.get(0).signedUrl().startsWith("/object/sign/" + bucket + "/folder/hello.txt?token="));
        assertNotNull(entries.get(1).error());
        assertEquals("missing.txt", entries.get(1).path());
        assertNull(entries.get(1).signedUrl());
    }

    @Test
    void signedUploadUrlsUploadWithoutCredentials() {
        String bucket = createBucket("sign-upload", false);

        SignedUploadUrlResponse signed = client.signUploadUrl(service, bucket, "uploads/hello.txt", null).body();
        assertTrue(signed.url().startsWith("/object/upload/sign/" + bucket + "/uploads/hello.txt?token="), signed.url());
        assertNotNull(signed.token());

        UploadObjectResponse uploaded = client.uploadSignedObject(bucket, "uploads/hello.txt", signed.token(), TEXT_PLAIN, "max-age=30", HELLO).body();
        assertEquals(bucket + "/uploads/hello.txt", uploaded.key());
        assertArrayEquals(HELLO, client.getObject(service, bucket, "uploads/hello.txt", null, null).body());

        assertError(HttpStatus.BAD_REQUEST, "KeyAlreadyExists",
            () -> client.uploadSignedObject(bucket, "uploads/hello.txt", client.signUploadUrl(service, bucket, "uploads/hello.txt", null).body().token(), TEXT_PLAIN, null, HELLO));
        String upsertToken = client.signUploadUrl(service, bucket, "uploads/hello.txt", true).body().token();
        byte[] replacement = "replaced".getBytes(StandardCharsets.UTF_8);
        client.uploadSignedObject(bucket, "uploads/hello.txt", upsertToken, TEXT_PLAIN, null, replacement);
        assertArrayEquals(replacement, client.getObject(service, bucket, "uploads/hello.txt", null, null).body());
    }

    // ------------------------------------------------------------------ image transformation and CDN

    @Test
    void renderRoutesAreAbsentWhenImageTransformationIsDisabled() {
        String bucket = createBucket("render", true);
        client.uploadObject(service, bucket, "image.png", "image/png", null, null, null, HELLO);

        assertEquals(HttpStatus.NOT_FOUND, client.renderPublicImage(bucket, "image.png", 10, 10, "cover", null, null, null, null, null, null).getStatus());
        assertEquals(HttpStatus.NOT_FOUND, client.renderAuthenticatedImage(service, bucket, "image.png", 10, null, null, "webp", 80, "ce", 0.5, 0.5, null).getStatus());
        assertEquals(HttpStatus.NOT_FOUND, client.renderSignedImage(bucket, "image.png", "token", null).getStatus());
    }

    @Test
    void cdnPurgeNeedsAPurgeEndpoint() {
        String bucket = createBucket("cdn", true);

        assertError(HttpStatus.BAD_REQUEST, "MissingParameter", () -> client.purgeCache(service, null));
        assertError(HttpStatus.BAD_REQUEST, "MissingParameter", () -> client.purgeBucketCache(service, bucket, true));
        assertError(HttpStatus.BAD_REQUEST, "MissingParameter", () -> client.purgeObjectCache(service, bucket, "folder/image.png", false));
    }

    // ------------------------------------------------------------------ validation

    @Test
    void invalidParametersAreRejectedBeforeTheRequestIsSent() {
        assertThrows(ConstraintViolationException.class, () -> client.getBucket(service, ""));
        assertThrows(ConstraintViolationException.class, () -> client.createBucket(service, new CreateBucketRequest(" ", null, null, null, null, null, null)));
        assertThrows(ConstraintViolationException.class, () -> client.deleteObjects(service, "bucket", new DeleteObjectsRequest(List.of())));
        assertThrows(ConstraintViolationException.class, () -> client.signObject(service, "bucket", "key", new SignObjectRequest(0, null, null)));
        assertThrows(ConstraintViolationException.class, () -> client.uploadObject("", "bucket", "key", TEXT_PLAIN, null, null, null, HELLO));
    }

    // ------------------------------------------------------------------ helpers

    private String createBucket(String prefix, boolean isPublic) {
        String name = uniqueBucket(prefix);
        client.createBucket(service, new CreateBucketRequest(name, null, isPublic, null, null, null, null));
        return name;
    }

    private static String uniqueBucket(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Storage answers rejected requests with HTTP {@code 400} for most causes; the body carries the real status
     * in {@code statusCode} and a stable {@code code}, which this asserts on.
     */
    private static HttpResponse<?> errorResponse(Supplier<HttpResponse<?>> call) {
        try {
            HttpResponse<?> response = call.get();
            assertTrue(response.getStatus().getCode() >= 400, () -> "expected an error response but got " + response.getStatus());
            return response;
        } catch (HttpClientResponseException e) {
            return e.getResponse();
        }
    }

    private static void assertError(HttpStatus status, String code, Supplier<HttpResponse<?>> call) {
        HttpResponse<?> errorResponse = errorResponse(call);
        StorageErrorSchema error = errorResponse.getBody(Argument.of(StorageErrorSchema.class)).orElse(null);
        assertNotNull(error, () -> "no error body in " + errorResponse.getStatus());
        assertEquals(status, errorResponse.getStatus(), () -> "unexpected status, body: " + error);
        assertEquals(code, error.code(), () -> "unexpected code, body: " + error);
    }
}
