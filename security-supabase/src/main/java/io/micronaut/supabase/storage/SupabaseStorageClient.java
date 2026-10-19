/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.supabase.storage;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.Put;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.supabase.SupabaseApiKeyClientFilter;
import io.micronaut.supabase.SupabaseConfiguration;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

/**
 * Declarative client for the Supabase Storage REST API.
 *
 * <p>For a hosted project set {@code supabase.project-id}, or {@code supabase.url} for a custom domain, and
 * {@link io.micronaut.supabase.SupabaseDiscoveryClient} resolves the client to the project URL. Requests are
 * sent below the Storage API path, {@code supabase.storage-path}, which defaults to {@code /storage/v1}. For a
 * Storage API server that is not behind the Supabase gateway set {@code micronaut.http.services.supabase.url}
 * to its URL and {@code supabase.storage-path} to an empty string.</p>
 *
 * <p>Credentials are split between configuration and method parameters:</p>
 * <ul>
 *   <li>The project API key is configured once through {@link io.micronaut.supabase.SupabaseConfiguration}
 *       and added to every request by {@link io.micronaut.supabase.SupabaseApiKeyClientFilter}. A Storage API
 *       server reached directly ignores it.</li>
 *   <li>{@code authorization} parameters take a full {@code Authorization} header value including the
 *       {@code Bearer} scheme. Storage enforces the project's Row Level Security policies with the role of
 *       the token: a signed-in user's access token acts as that user, a legacy service-role JWT bypasses the
 *       policies. The public routes take no authorization and only serve objects of public buckets.</li>
 * </ul>
 *
 * <p>Objects are addressed by bucket name and key; keys may contain slashes, which the client leaves
 * unencoded. Rejected requests surface as
 * {@link io.micronaut.http.client.exceptions.HttpClientResponseException} whose body deserializes to
 * {@link StorageErrorSchema}, except {@code 404} responses, which methods returning {@link HttpResponse}
 * return as-is. The server answers most rejected requests with HTTP status {@code 400} and reports the
 * status describing the cause in the body. When Micronaut Validation is on the classpath, parameters are
 * validated before the request is sent.</p>
 *
 * @see <a href="https://supabase.github.io/storage/api.json">Supabase Storage API OpenAPI document</a>
 * @since 0.0.1
 */
@Experimental
@Client(id = SupabaseApiKeyClientFilter.SERVICE_ID, path = "${" + SupabaseConfiguration.STORAGE_PATH_PROPERTY + ":" + SupabaseConfiguration.STORAGE_PATH + "}")
public interface SupabaseStorageClient {

    /**
     * Header that requests replacing an existing object on upload.
     */
    String UPSERT_HEADER = "x-upsert";

    /**
     * Header carrying user metadata on upload: a base64-encoded JSON object.
     */
    String METADATA_HEADER = "x-metadata";

    // ------------------------------------------------------------------ health

    /**
     * Reports whether the server can reach its database. The route needs a valid token of any role.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @return A body with {@code healthy} set to {@code true}
     * @since 0.0.1
     */
    @Get("/health")
    HttpResponse<Map<String, Object>> health(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization);

    // ------------------------------------------------------------------ buckets

    /**
     * Creates a bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param request Bucket properties
     * @return The name of the created bucket
     * @since 0.0.1
     */
    @Post("/bucket")
    HttpResponse<CreateBucketResponse> createBucket(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                    @Body @Valid CreateBucketRequest request);

    /**
     * Lists the buckets the token may see.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param limit Maximum number of buckets
     * @param offset Number of buckets to skip
     * @param sortColumn Column to sort by: {@code id}, {@code name}, {@code created_at} or {@code updated_at}
     * @param sortOrder {@code asc} or {@code desc}
     * @param search Text the bucket names must contain
     * @return The buckets
     * @since 0.0.1
     */
    @Get("/bucket{?limit,offset,sortColumn,sortOrder,search}")
    HttpResponse<List<BucketSchema>> listBuckets(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                 @QueryValue("limit") @Nullable Integer limit,
                                                 @QueryValue("offset") @Nullable Integer offset,
                                                 @QueryValue("sortColumn") @Nullable String sortColumn,
                                                 @QueryValue("sortOrder") @Nullable String sortOrder,
                                                 @QueryValue("search") @Nullable String search);

    /**
     * Gets the details of a bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketId Bucket identifier
     * @return The bucket
     * @since 0.0.1
     */
    @Get("/bucket/{bucketId}")
    HttpResponse<BucketSchema> getBucket(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                         @PathVariable("bucketId") @NotBlank String bucketId);

    /**
     * Updates the properties of a bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketId Bucket identifier
     * @param request Properties to change
     * @return A confirmation message
     * @since 0.0.1
     */
    @Put("/bucket/{bucketId}")
    HttpResponse<MessageResponse> updateBucket(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                               @PathVariable("bucketId") @NotBlank String bucketId,
                                               @Body @Valid UpdateBucketRequest request);

    /**
     * Deletes an empty bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketId Bucket identifier
     * @return A confirmation message
     * @since 0.0.1
     */
    @Delete("/bucket/{bucketId}")
    HttpResponse<MessageResponse> deleteBucket(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                               @PathVariable("bucketId") @NotBlank String bucketId);

    /**
     * Queues the deletion of every object of a bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketId Bucket identifier
     * @return A confirmation message; the deletion completes asynchronously
     * @since 0.0.1
     */
    @Post("/bucket/{bucketId}/empty")
    HttpResponse<MessageResponse> emptyBucket(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                              @PathVariable("bucketId") @NotBlank String bucketId);

    /**
     * Gets the lifecycle configuration of a bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketId Bucket identifier
     * @return The lifecycle configuration; code {@code NoSuchLifecycleConfiguration} when none is set
     * @since 0.0.1
     */
    @Get("/bucket/{bucketId}/lifecycle")
    HttpResponse<LifecycleConfiguration> getBucketLifecycle(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                            @PathVariable("bucketId") @NotBlank String bucketId);

    /**
     * Replaces the lifecycle configuration of a bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketId Bucket identifier
     * @param configuration The full lifecycle configuration
     * @return The stored configuration, with rule identifiers assigned
     * @since 0.0.1
     */
    @Put("/bucket/{bucketId}/lifecycle")
    HttpResponse<LifecycleConfiguration> putBucketLifecycle(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                            @PathVariable("bucketId") @NotBlank String bucketId,
                                                            @Body @Valid LifecycleConfiguration configuration);

    /**
     * Deletes the lifecycle configuration of a bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketId Bucket identifier
     * @return A confirmation message
     * @since 0.0.1
     */
    @Delete("/bucket/{bucketId}/lifecycle")
    HttpResponse<MessageResponse> deleteBucketLifecycle(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                        @PathVariable("bucketId") @NotBlank String bucketId);

    // ------------------------------------------------------------------ objects

    /**
     * Uploads a new object. Fails with code {@code KeyAlreadyExists} when the key exists and upsert is not
     * requested.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key, which may contain slashes
     * @param contentType MIME type stored with the object
     * @param cacheControl {@code Cache-Control} value served with the object, such as {@code max-age=3600}
     * @param upsert Whether to replace an existing object
     * @param metadata User metadata as a base64-encoded JSON object
     * @param body Object content
     * @return The identifier and key of the object
     * @since 0.0.1
     */
    @Post("/object/{bucketName}/{+objectKey}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    HttpResponse<UploadObjectResponse> uploadObject(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                    @PathVariable("bucketName") @NotBlank String bucketName,
                                                    @PathVariable("objectKey") @NotBlank String objectKey,
                                                    @Header(HttpHeaders.CONTENT_TYPE) @NotBlank String contentType,
                                                    @Header(HttpHeaders.CACHE_CONTROL) @Nullable String cacheControl,
                                                    @Header(UPSERT_HEADER) @Nullable Boolean upsert,
                                                    @Header(METADATA_HEADER) @Nullable String metadata,
                                                    @Body byte[] body);

    /**
     * Replaces the content of an existing object.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param contentType MIME type stored with the object
     * @param cacheControl {@code Cache-Control} value served with the object
     * @param metadata User metadata as a base64-encoded JSON object
     * @param body New object content
     * @return The identifier and key of the object
     * @since 0.0.1
     */
    @Put("/object/{bucketName}/{+objectKey}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    HttpResponse<UploadObjectResponse> updateObject(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                    @PathVariable("bucketName") @NotBlank String bucketName,
                                                    @PathVariable("objectKey") @NotBlank String objectKey,
                                                    @Header(HttpHeaders.CONTENT_TYPE) @NotBlank String contentType,
                                                    @Header(HttpHeaders.CACHE_CONTROL) @Nullable String cacheControl,
                                                    @Header(METADATA_HEADER) @Nullable String metadata,
                                                    @Body byte[] body);

    /**
     * Downloads an object the token may read.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param download When present the object is served as an attachment; a non-empty value names the file
     * @param versionId Version to download, defaults to the current one
     * @return The object content, with {@code Content-Type}, {@code ETag} and {@code Cache-Control} headers
     * @since 0.0.1
     */
    @Get("/object/{bucketName}/{+objectKey}{?download,versionId}")
    HttpResponse<byte[]> getObject(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                   @PathVariable("bucketName") @NotBlank String bucketName,
                                   @PathVariable("objectKey") @NotBlank String objectKey,
                                   @QueryValue("download") @Nullable String download,
                                   @QueryValue("versionId") @Nullable String versionId);

    /**
     * Downloads an object through the authenticated route, which never falls back to public access.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param download When present the object is served as an attachment; a non-empty value names the file
     * @param versionId Version to download, defaults to the current one
     * @return The object content
     * @since 0.0.1
     */
    @Get("/object/authenticated/{bucketName}/{+objectKey}{?download,versionId}")
    HttpResponse<byte[]> getAuthenticatedObject(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                @PathVariable("bucketName") @NotBlank String bucketName,
                                                @PathVariable("objectKey") @NotBlank String objectKey,
                                                @QueryValue("download") @Nullable String download,
                                                @QueryValue("versionId") @Nullable String versionId);

    /**
     * Downloads an object of a public bucket without credentials.
     *
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param download When present the object is served as an attachment; a non-empty value names the file
     * @param versionId Version to download, defaults to the current one
     * @return The object content; code {@code NoSuchBucket} when the bucket is not public
     * @since 0.0.1
     */
    @Get("/object/public/{bucketName}/{+objectKey}{?download,versionId}")
    HttpResponse<byte[]> getPublicObject(@PathVariable("bucketName") @NotBlank String bucketName,
                                         @PathVariable("objectKey") @NotBlank String objectKey,
                                         @QueryValue("download") @Nullable String download,
                                         @QueryValue("versionId") @Nullable String versionId);

    /**
     * Gets the metadata of an object the token may read.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param versionId Version to describe, defaults to the current one
     * @return The object metadata
     * @since 0.0.1
     */
    @Get("/object/info/{bucketName}/{+objectKey}{?versionId}")
    HttpResponse<ObjectInfoSchema> getObjectInfo(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                 @PathVariable("bucketName") @NotBlank String bucketName,
                                                 @PathVariable("objectKey") @NotBlank String objectKey,
                                                 @QueryValue("versionId") @Nullable String versionId);

    /**
     * Gets the metadata of an object through the authenticated route.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param versionId Version to describe, defaults to the current one
     * @return The object metadata
     * @since 0.0.1
     */
    @Get("/object/info/authenticated/{bucketName}/{+objectKey}{?versionId}")
    HttpResponse<ObjectInfoSchema> getAuthenticatedObjectInfo(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                              @PathVariable("bucketName") @NotBlank String bucketName,
                                                              @PathVariable("objectKey") @NotBlank String objectKey,
                                                              @QueryValue("versionId") @Nullable String versionId);

    /**
     * Gets the metadata of an object of a public bucket without credentials.
     *
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param versionId Version to describe, defaults to the current one
     * @return The object metadata
     * @since 0.0.1
     */
    @Get("/object/info/public/{bucketName}/{+objectKey}{?versionId}")
    HttpResponse<ObjectInfoSchema> getPublicObjectInfo(@PathVariable("bucketName") @NotBlank String bucketName,
                                                       @PathVariable("objectKey") @NotBlank String objectKey,
                                                       @QueryValue("versionId") @Nullable String versionId);

    /**
     * Deletes an object, or one version of it.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param versionId Version to delete, defaults to the current one
     * @return A confirmation message; code {@code NoSuchKey} when the object does not exist
     * @since 0.0.1
     */
    @Delete("/object/{bucketName}/{+objectKey}{?versionId}")
    HttpResponse<MessageResponse> deleteObject(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                               @PathVariable("bucketName") @NotBlank String bucketName,
                                               @PathVariable("objectKey") @NotBlank String objectKey,
                                               @QueryValue("versionId") @Nullable String versionId);

    /**
     * Deletes several objects. Keys that do not exist are ignored.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param request Keys to delete
     * @return The objects that were deleted
     * @since 0.0.1
     */
    @Delete("/object/{bucketName}")
    HttpResponse<List<ObjectSchema>> deleteObjects(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                   @PathVariable("bucketName") @NotBlank String bucketName,
                                                   @Body @Valid DeleteObjectsRequest request);

    /**
     * Lists the objects of a folder, with offset pagination.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param request Folder, pagination and sort options
     * @return The objects, named relative to the folder
     * @since 0.0.1
     */
    @Post("/object/list/{bucketName}")
    HttpResponse<List<ObjectSchema>> listObjects(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                 @PathVariable("bucketName") @NotBlank String bucketName,
                                                 @Body @Valid ListObjectsRequest request);

    /**
     * Lists the objects below a prefix, with cursor pagination.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param request Prefix, pagination and sort options
     * @return One page of objects and folders
     * @since 0.0.1
     */
    @Post("/object/list-v2/{bucketName}")
    HttpResponse<ListObjectsV2Response> listObjectsV2(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                      @PathVariable("bucketName") @NotBlank String bucketName,
                                                      @Body @Valid ListObjectsV2Request request);

    /**
     * Moves an object to another key, possibly in another bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param request Source and destination
     * @return A confirmation message
     * @since 0.0.1
     */
    @Post("/object/move")
    HttpResponse<MessageResponse> moveObject(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                             @Body @Valid MoveObjectRequest request);

    /**
     * Copies an object to another key, possibly in another bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param request Source, destination and metadata options
     * @return The copy
     * @since 0.0.1
     */
    @Post("/object/copy")
    HttpResponse<CopyObjectResponse> copyObject(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                @Body @Valid CopyObjectRequest request);

    // ------------------------------------------------------------------ signed URLs

    /**
     * Creates a signed URL to download an object without credentials.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param request Validity and optional transformation
     * @return The signed URL, relative to the Storage API
     * @since 0.0.1
     */
    @Post("/object/sign/{bucketName}/{+objectKey}")
    HttpResponse<SignedUrlResponse> signObject(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                               @PathVariable("bucketName") @NotBlank String bucketName,
                                               @PathVariable("objectKey") @NotBlank String objectKey,
                                               @Body @Valid SignObjectRequest request);

    /**
     * Creates signed URLs for several objects. Objects that cannot be signed are reported per entry.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param request Validity and object keys
     * @return One entry per requested key
     * @since 0.0.1
     */
    @Post("/object/sign/{bucketName}")
    HttpResponse<List<SignedUrlEntry>> signObjects(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                   @PathVariable("bucketName") @NotBlank String bucketName,
                                                   @Body @Valid SignObjectsRequest request);

    /**
     * Downloads an object through a signed URL.
     *
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param token Token from the signed URL
     * @param download When present the object is served as an attachment; a non-empty value names the file
     * @return The object content; code {@code InvalidJWT} for a token that is not valid
     * @since 0.0.1
     */
    @Get("/object/sign/{bucketName}/{+objectKey}?token={token}{&download}")
    HttpResponse<byte[]> getSignedObject(@PathVariable("bucketName") @NotBlank String bucketName,
                                         @PathVariable("objectKey") @NotBlank String objectKey,
                                         @QueryValue("token") @NotBlank String token,
                                         @QueryValue("download") @Nullable String download);

    /**
     * Creates a signed URL that lets its holder upload an object without credentials.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Key of the object to upload
     * @param upsert Whether the upload may replace an existing object
     * @return The signed upload URL and its token
     * @since 0.0.1
     */
    @Post("/object/upload/sign/{bucketName}/{+objectKey}")
    HttpResponse<SignedUploadUrlResponse> signUploadUrl(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                        @PathVariable("bucketName") @NotBlank String bucketName,
                                                        @PathVariable("objectKey") @NotBlank String objectKey,
                                                        @Header(UPSERT_HEADER) @Nullable Boolean upsert);

    /**
     * Uploads an object through a signed upload URL.
     *
     * @param bucketName Bucket name
     * @param objectKey Object key, the one the URL was signed for
     * @param token Token from the signed upload URL
     * @param contentType MIME type stored with the object
     * @param cacheControl {@code Cache-Control} value served with the object
     * @param body Object content
     * @return The key of the object
     * @since 0.0.1
     */
    @Put("/object/upload/sign/{bucketName}/{+objectKey}?token={token}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    HttpResponse<UploadObjectResponse> uploadSignedObject(@PathVariable("bucketName") @NotBlank String bucketName,
                                                          @PathVariable("objectKey") @NotBlank String objectKey,
                                                          @QueryValue("token") @NotBlank String token,
                                                          @Header(HttpHeaders.CONTENT_TYPE) @NotBlank String contentType,
                                                          @Header(HttpHeaders.CACHE_CONTROL) @Nullable String cacheControl,
                                                          @Body byte[] body);

    // ------------------------------------------------------------------ image transformation

    /**
     * Renders an image the token may read with the given transformation. Requires image transformation to be
     * enabled on the server, otherwise the route does not exist.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param width Width in pixels
     * @param height Height in pixels
     * @param resize Resize mode, {@code cover}, {@code contain} or {@code fill}
     * @param format Output format, {@code origin}, {@code avif} or {@code webp}
     * @param quality Output quality from 20 to 100
     * @param gravity Crop gravity
     * @param xOffset Horizontal gravity offset
     * @param yOffset Vertical gravity offset
     * @param download When present the image is served as an attachment; a non-empty value names the file
     * @return The rendered image of the current version
     * @since 0.0.1
     */
    @Get("/render/image/authenticated/{bucketName}/{+objectKey}{?width,height,resize,format,quality,gravity,x_offset,y_offset,download}")
    HttpResponse<byte[]> renderAuthenticatedImage(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                  @PathVariable("bucketName") @NotBlank String bucketName,
                                                  @PathVariable("objectKey") @NotBlank String objectKey,
                                                  @QueryValue("width") @Nullable Integer width,
                                                  @QueryValue("height") @Nullable Integer height,
                                                  @QueryValue("resize") @Nullable String resize,
                                                  @QueryValue("format") @Nullable String format,
                                                  @QueryValue("quality") @Nullable Integer quality,
                                                  @QueryValue("gravity") @Nullable String gravity,
                                                  @QueryValue("x_offset") @Nullable Double xOffset,
                                                  @QueryValue("y_offset") @Nullable Double yOffset,
                                                  @QueryValue("download") @Nullable String download);

    /**
     * Renders an image of a public bucket with the given transformation, without credentials.
     *
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param width Width in pixels
     * @param height Height in pixels
     * @param resize Resize mode, {@code cover}, {@code contain} or {@code fill}
     * @param format Output format, {@code origin}, {@code avif} or {@code webp}
     * @param quality Output quality from 20 to 100
     * @param gravity Crop gravity
     * @param xOffset Horizontal gravity offset
     * @param yOffset Vertical gravity offset
     * @param download When present the image is served as an attachment; a non-empty value names the file
     * @return The rendered image of the current version
     * @since 0.0.1
     */
    @Get("/render/image/public/{bucketName}/{+objectKey}{?width,height,resize,format,quality,gravity,x_offset,y_offset,download}")
    HttpResponse<byte[]> renderPublicImage(@PathVariable("bucketName") @NotBlank String bucketName,
                                           @PathVariable("objectKey") @NotBlank String objectKey,
                                           @QueryValue("width") @Nullable Integer width,
                                           @QueryValue("height") @Nullable Integer height,
                                           @QueryValue("resize") @Nullable String resize,
                                           @QueryValue("format") @Nullable String format,
                                           @QueryValue("quality") @Nullable Integer quality,
                                           @QueryValue("gravity") @Nullable String gravity,
                                           @QueryValue("x_offset") @Nullable Double xOffset,
                                           @QueryValue("y_offset") @Nullable Double yOffset,
                                           @QueryValue("download") @Nullable String download);

    /**
     * Renders an image through a signed URL whose transformation was fixed when it was signed.
     *
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param token Token from the signed URL
     * @param download When present the image is served as an attachment; a non-empty value names the file
     * @return The rendered image
     * @since 0.0.1
     */
    @Get("/render/image/sign/{bucketName}/{+objectKey}?token={token}{&download}")
    HttpResponse<byte[]> renderSignedImage(@PathVariable("bucketName") @NotBlank String bucketName,
                                           @PathVariable("objectKey") @NotBlank String objectKey,
                                           @QueryValue("token") @NotBlank String token,
                                           @QueryValue("download") @Nullable String download);

    // ------------------------------------------------------------------ CDN

    /**
     * Purges the CDN cache of the whole project. Requires a CDN purge endpoint to be configured on the server.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param transformations Whether to purge only the cached image transformations
     * @return A confirmation message
     * @since 0.0.1
     */
    @Delete("/cdn{?transformations}")
    HttpResponse<MessageResponse> purgeCache(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                             @QueryValue("transformations") @Nullable Boolean transformations);

    /**
     * Purges the CDN cache of a bucket.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param transformations Whether to purge only the cached image transformations
     * @return A confirmation message
     * @since 0.0.1
     */
    @Delete("/cdn/{bucketName}{?transformations}")
    HttpResponse<MessageResponse> purgeBucketCache(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                   @PathVariable("bucketName") @NotBlank String bucketName,
                                                   @QueryValue("transformations") @Nullable Boolean transformations);

    /**
     * Purges the CDN cache of an object.
     *
     * @param authorization Authorization header value, including the {@code Bearer} scheme
     * @param bucketName Bucket name
     * @param objectKey Object key
     * @param transformations Whether to purge only the cached image transformations
     * @return A confirmation message
     * @since 0.0.1
     */
    @Delete("/cdn/{bucketName}/{+objectKey}{?transformations}")
    HttpResponse<MessageResponse> purgeObjectCache(@Header(HttpHeaders.AUTHORIZATION) @NotBlank String authorization,
                                                   @PathVariable("bucketName") @NotBlank String bucketName,
                                                   @PathVariable("objectKey") @NotBlank String objectKey,
                                                   @QueryValue("transformations") @Nullable Boolean transformations);
}
