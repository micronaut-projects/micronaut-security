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
package io.micronaut.security.scim.data.jdbc.http.service;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpStatus;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.scim.core.Address;
import io.micronaut.security.scim.core.EnterpriseUser;
import io.micronaut.security.scim.core.Manager;
import io.micronaut.security.scim.core.MultiValuedAttribute;
import io.micronaut.security.scim.core.Name;
import io.micronaut.security.scim.core.ResourceReference;
import io.micronaut.security.scim.core.User;
import io.micronaut.security.scim.data.entities.ScimEnterpriseUserEntity;
import io.micronaut.security.scim.data.entities.ScimGroupEntity;
import io.micronaut.security.scim.data.entities.ScimGroupMemberEntity;
import io.micronaut.security.scim.data.entities.ScimResourceType;
import io.micronaut.security.scim.data.entities.ScimUserAddressEntity;
import io.micronaut.security.scim.data.entities.ScimUserAttributeEntity;
import io.micronaut.security.scim.data.entities.ScimUserAttributeKind;
import io.micronaut.security.scim.data.entities.ScimUserEntity;
import io.micronaut.security.scim.data.jdbc.repositories.ScimEnterpriseUserJdbcRepository;
import io.micronaut.security.scim.data.jdbc.repositories.ScimGroupJdbcRepository;
import io.micronaut.security.scim.data.jdbc.repositories.ScimGroupMemberJdbcRepository;
import io.micronaut.security.scim.data.jdbc.repositories.ScimResourceExtensionJdbcRepository;
import io.micronaut.security.scim.data.jdbc.repositories.ScimUserAddressJdbcRepository;
import io.micronaut.security.scim.data.jdbc.repositories.ScimUserAttributeJdbcRepository;
import io.micronaut.security.scim.data.jdbc.repositories.ScimUserJdbcRepository;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.filter.ScimFilterParser;
import io.micronaut.security.scim.server.model.ScimPage;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.model.ScimResourceResponse;
import io.micronaut.security.scim.server.protocol.ScimErrorType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import io.micronaut.security.scim.server.service.ScimUserService;
import jakarta.inject.Singleton;
import jakarta.transaction.Transactional;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Default blocking {@link ScimUserService} backed by the SCIM JDBC repositories.
 *
 * @since 5.4.0
 */
@Singleton
@Experimental
@Requires(missingBeans = ScimUserService.class)
public class DefaultJdbcScimUserService implements ScimUserService {
    private static final Argument<User> USER_ARGUMENT = Argument.of(User.class);

    private final ScimUserJdbcRepository userRepository;
    private final ScimUserAddressJdbcRepository addressRepository;
    private final ScimUserAttributeJdbcRepository attributeRepository;
    private final ScimEnterpriseUserJdbcRepository enterpriseUserRepository;
    private final ScimGroupJdbcRepository groupRepository;
    private final ScimGroupMemberJdbcRepository groupMemberRepository;
    private final ScimResourceExtensionJdbcRepository extensionRepository;
    private final ScimResourceIdGenerator idGenerator;
    private final JsonMapper jsonMapper;
    private final ScimFilterParser filterParser;

    /**
     * @param userRepository User repository
     * @param addressRepository User address repository
     * @param attributeRepository User multi-valued attribute repository
     * @param enterpriseUserRepository Enterprise User extension repository
     * @param groupRepository Group repository
     * @param groupMemberRepository Group membership repository
     * @param extensionRepository Custom extension repository
     * @param idGenerator Resource identifier generator
     * @param jsonMapper JSON mapper used for extension and PATCH values
     * @param filterParser Parser used for PATCH value-selection filters
     * @since 5.4.0
     */
    public DefaultJdbcScimUserService(
        ScimUserJdbcRepository userRepository,
        ScimUserAddressJdbcRepository addressRepository,
        ScimUserAttributeJdbcRepository attributeRepository,
        ScimEnterpriseUserJdbcRepository enterpriseUserRepository,
        ScimGroupJdbcRepository groupRepository,
        ScimGroupMemberJdbcRepository groupMemberRepository,
        ScimResourceExtensionJdbcRepository extensionRepository,
        ScimResourceIdGenerator idGenerator,
        JsonMapper jsonMapper,
        ScimFilterParser filterParser
    ) {
        this.userRepository = userRepository;
        this.addressRepository = addressRepository;
        this.attributeRepository = attributeRepository;
        this.enterpriseUserRepository = enterpriseUserRepository;
        this.groupRepository = groupRepository;
        this.groupMemberRepository = groupMemberRepository;
        this.extensionRepository = extensionRepository;
        this.idGenerator = idGenerator;
        this.jsonMapper = jsonMapper;
        this.filterParser = filterParser;
    }

    @Override
    @Transactional
    public ScimResourceResponse<User> create(User resource, ScimRequestContext context) {
        validate(resource, null);
        String id = idGenerator.generateId(ScimResourceType.USER);
        ScimUserEntity saved = userRepository.save(toEntity(resource, id, null));
        storeRelated(resource, id);
        return loadResponse(saved, context);
    }

    @Override
    @Transactional
    public Optional<ScimResourceResponse<User>> get(String id, ScimRequestContext context) {
        return userRepository.findById(id).map(entity -> loadResponse(entity, context));
    }

    @Override
    @Transactional
    public ScimPage<User> search(ScimQuery query, ScimRequestContext context) {
        List<User> users = new ArrayList<>();
        userRepository.findAll().forEach(entity -> users.add(loadResponse(entity, context).resource()));
        return JdbcScimQueryProcessor.process(users, query);
    }

    @Override
    @Transactional
    public Optional<ScimResourceResponse<User>> replace(
        String id,
        User resource,
        ScimRequestContext context
    ) {
        Optional<ScimUserEntity> existing = userRepository.findById(id);
        if (existing.isEmpty()) {
            return Optional.empty();
        }
        ScimUserEntity current = existing.get();
        JdbcScimServiceSupport.verifyIfMatch(context.ifMatch(), current.version());
        validate(resource, id);
        ScimUserEntity updated = userRepository.update(toEntity(resource, id, current));
        deleteRelated(id);
        storeRelated(resource, id);
        return Optional.of(loadResponse(updated, context));
    }

    @Override
    @Transactional
    public Optional<ScimResourceResponse<User>> patch(
        String id,
        ScimPatchRequest patch,
        ScimRequestContext context
    ) {
        Optional<ScimResourceResponse<User>> existing = get(id, context);
        if (existing.isEmpty()) {
            return Optional.empty();
        }
        User patched = JdbcScimServiceSupport.applyPatch(
            existing.get().resource(), patch, USER_ARGUMENT, jsonMapper, filterParser);
        return replace(id, patched, context);
    }

    @Override
    @Transactional
    public void delete(String id, ScimRequestContext context) {
        ScimUserEntity existing = userRepository.findById(id)
            .orElseThrow(() -> new ScimException(HttpStatus.NOT_FOUND, "No SCIM User exists with id " + id));
        JdbcScimServiceSupport.verifyIfMatch(context.ifMatch(), existing.version());
        deleteRelated(id);
        groupMemberRepository.deleteByMemberIdAndMemberType(id, ScimResourceType.USER);
        userRepository.delete(existing);
    }

    private ScimResourceResponse<User> loadResponse(ScimUserEntity entity, ScimRequestContext context) {
        User user = toResource(entity, context);
        return JdbcScimServiceSupport.response(
            user,
            "User",
            entity.created(),
            entity.lastModified(),
            entity.version(),
            "Users",
            context
        );
    }

    private User toResource(ScimUserEntity entity, ScimRequestContext context) {
        User user = new User();
        user.setId(entity.id());
        user.setExternalId(entity.externalId());
        user.setUserName(entity.userName());
        if (hasName(entity)) {
            user.setName(new Name(
                entity.nameFormatted(),
                entity.nameFamilyName(),
                entity.nameGivenName(),
                entity.nameMiddleName(),
                entity.nameHonorificPrefix(),
                entity.nameHonorificSuffix()
            ));
        }
        user.setDisplayName(entity.displayName());
        user.setNickName(entity.nickName());
        user.setProfileUrl(entity.profileUrl());
        user.setTitle(entity.title());
        user.setUserType(entity.userType());
        user.setPreferredLanguage(entity.preferredLanguage());
        user.setLocale(entity.locale());
        user.setTimezone(entity.timezone());
        user.setActive(entity.active());
        user.setAddresses(addressRepository.findAllByUserIdOrderByPosition(entity.id()).stream()
            .map(DefaultJdbcScimUserService::toAddress)
            .toList());
        setAttributes(user, attributeRepository.findAllByUserIdOrderByAttributeKindAndPosition(entity.id()));
        enterpriseUserRepository.findById(entity.id()).ifPresent(value -> user.setEnterpriseUser(toEnterpriseUser(value)));
        List<ResourceReference> groups = groupMemberRepository
            .findAllByMemberIdAndMemberType(entity.id(), ScimResourceType.USER)
            .stream()
            .map(membership -> toGroupReference(membership, context))
            .toList();
        user.setGroups(groups);
        JdbcScimServiceSupport.loadExtensions(
            user, ScimResourceType.USER, entity.id(), extensionRepository, jsonMapper);
        return user;
    }

    private ScimUserEntity toEntity(User user, String id, @Nullable ScimUserEntity existing) {
        Name name = user.getName();
        return new ScimUserEntity(
            id,
            user.getExternalId(),
            requiredUserName(user),
            name == null ? null : name.formatted(),
            name == null ? null : name.familyName(),
            name == null ? null : name.givenName(),
            name == null ? null : name.middleName(),
            name == null ? null : name.honorificPrefix(),
            name == null ? null : name.honorificSuffix(),
            user.getDisplayName(),
            user.getNickName(),
            user.getProfileUrl(),
            user.getTitle(),
            user.getUserType(),
            user.getPreferredLanguage(),
            user.getLocale(),
            user.getTimezone(),
            user.getActive(),
            existing == null ? null : existing.version(),
            existing == null ? null : existing.created(),
            existing == null ? null : existing.lastModified()
        );
    }

    private void storeRelated(User user, String id) {
        storeAddresses(user.getAddresses(), id);
        storeAttributes(user.getEmails(), id, ScimUserAttributeKind.EMAIL);
        storeAttributes(user.getPhoneNumbers(), id, ScimUserAttributeKind.PHONE_NUMBER);
        storeAttributes(user.getIms(), id, ScimUserAttributeKind.IM);
        storeAttributes(user.getPhotos(), id, ScimUserAttributeKind.PHOTO);
        storeAttributes(user.getEntitlements(), id, ScimUserAttributeKind.ENTITLEMENT);
        storeAttributes(user.getRoles(), id, ScimUserAttributeKind.ROLE);
        storeAttributes(user.getX509Certificates(), id, ScimUserAttributeKind.X509_CERTIFICATE);
        storeEnterpriseUser(user.getEnterpriseUser(), id);
        JdbcScimServiceSupport.storeExtensions(
            user, ScimResourceType.USER, id, extensionRepository, jsonMapper);
    }

    private void deleteRelated(String id) {
        addressRepository.deleteByUserId(id);
        attributeRepository.deleteByUserId(id);
        if (enterpriseUserRepository.existsById(id)) {
            enterpriseUserRepository.deleteById(id);
        }
        extensionRepository.deleteByResourceTypeAndResourceId(ScimResourceType.USER, id);
    }

    private void storeAddresses(@Nullable List<Address> addresses, String userId) {
        if (addresses == null) {
            return;
        }
        verifySinglePrimary(addresses.stream().map(Address::primary).toList(), "addresses");
        for (int index = 0; index < addresses.size(); index++) {
            Address address = addresses.get(index);
            addressRepository.save(new ScimUserAddressEntity(
                null,
                userId,
                address.formatted(),
                address.streetAddress(),
                address.locality(),
                address.region(),
                address.postalCode(),
                address.country(),
                address.type(),
                address.primary(),
                index
            ));
        }
    }

    private void storeAttributes(
        @Nullable List<MultiValuedAttribute> values,
        String userId,
        ScimUserAttributeKind kind
    ) {
        if (values == null) {
            return;
        }
        verifySinglePrimary(values.stream().map(MultiValuedAttribute::primary).toList(), kind.name());
        for (int index = 0; index < values.size(); index++) {
            MultiValuedAttribute value = values.get(index);
            attributeRepository.save(new ScimUserAttributeEntity(
                null,
                userId,
                kind,
                value.value(),
                value.type(),
                value.primary(),
                value.display(),
                value.ref(),
                index
            ));
        }
    }

    private void storeEnterpriseUser(@Nullable EnterpriseUser enterpriseUser, String userId) {
        if (enterpriseUser == null) {
            return;
        }
        Manager manager = enterpriseUser.manager();
        enterpriseUserRepository.save(new ScimEnterpriseUserEntity(
            userId,
            enterpriseUser.employeeNumber(),
            enterpriseUser.costCenter(),
            enterpriseUser.organization(),
            enterpriseUser.division(),
            enterpriseUser.department(),
            manager == null ? null : manager.value(),
            manager == null ? null : manager.ref(),
            manager == null ? null : manager.displayName()
        ));
    }

    private void validate(User user, @Nullable String currentId) {
        String userName = requiredUserName(user);
        userRepository.findByUserNameIgnoreCase(userName).ifPresent(existing -> {
            if (!existing.id().equals(currentId)) {
                throw new ScimException(HttpStatus.CONFLICT, ScimErrorType.UNIQUENESS,
                    "A User with userName " + userName + " already exists");
            }
        });
        if (user.getPassword() != null) {
            throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.SENSITIVE,
                "The JDBC adapter does not persist passwords; provide an application ScimUserService to handle them");
        }
    }

    private ResourceReference toGroupReference(ScimGroupMemberEntity membership, ScimRequestContext context) {
        Optional<ScimGroupEntity> group = groupRepository.findById(membership.groupId());
        return new ResourceReference(
            membership.groupId(),
            JdbcScimServiceSupport.location(context, "Groups", membership.groupId()).toString(),
            group.map(ScimGroupEntity::displayName).orElse(null),
            "direct"
        );
    }

    private static void setAttributes(User user, List<ScimUserAttributeEntity> attributes) {
        Map<ScimUserAttributeKind, List<MultiValuedAttribute>> grouped =
            new EnumMap<>(ScimUserAttributeKind.class);
        for (ScimUserAttributeEntity attribute : attributes) {
            grouped.computeIfAbsent(attribute.attributeKind(), ignored -> new ArrayList<>())
                .add(toMultiValuedAttribute(attribute));
        }
        user.setEmails(grouped.getOrDefault(ScimUserAttributeKind.EMAIL, List.of()));
        user.setPhoneNumbers(grouped.getOrDefault(ScimUserAttributeKind.PHONE_NUMBER, List.of()));
        user.setIms(grouped.getOrDefault(ScimUserAttributeKind.IM, List.of()));
        user.setPhotos(grouped.getOrDefault(ScimUserAttributeKind.PHOTO, List.of()));
        user.setEntitlements(grouped.getOrDefault(ScimUserAttributeKind.ENTITLEMENT, List.of()));
        user.setRoles(grouped.getOrDefault(ScimUserAttributeKind.ROLE, List.of()));
        user.setX509Certificates(grouped.getOrDefault(ScimUserAttributeKind.X509_CERTIFICATE, List.of()));
    }

    private static MultiValuedAttribute toMultiValuedAttribute(ScimUserAttributeEntity value) {
        return new MultiValuedAttribute(
            value.value(), value.type(), value.primaryValue(), value.display(), value.referenceUri());
    }

    private static Address toAddress(ScimUserAddressEntity value) {
        return new Address(
            value.formatted(),
            value.streetAddress(),
            value.locality(),
            value.region(),
            value.postalCode(),
            value.country(),
            value.type(),
            value.primaryValue()
        );
    }

    private static EnterpriseUser toEnterpriseUser(ScimEnterpriseUserEntity value) {
        Manager manager = value.managerValue() == null
            && value.managerReferenceUri() == null
            && value.managerDisplayName() == null
            ? null
            : new Manager(value.managerValue(), value.managerReferenceUri(), value.managerDisplayName());
        return new EnterpriseUser(
            value.employeeNumber(),
            value.costCenter(),
            value.organization(),
            value.division(),
            value.department(),
            manager
        );
    }

    private static boolean hasName(ScimUserEntity entity) {
        return entity.nameFormatted() != null
            || entity.nameFamilyName() != null
            || entity.nameGivenName() != null
            || entity.nameMiddleName() != null
            || entity.nameHonorificPrefix() != null
            || entity.nameHonorificSuffix() != null;
    }

    private static String requiredUserName(User user) {
        if (user.getUserName() == null || user.getUserName().isBlank()) {
            throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_VALUE,
                "userName must not be blank");
        }
        return user.getUserName();
    }

    private static void verifySinglePrimary(List<@Nullable Boolean> primaryValues, String attribute) {
        if (primaryValues.stream().filter(Boolean.TRUE::equals).count() > 1) {
            throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_VALUE,
                attribute + " must not contain more than one primary value");
        }
    }
}
