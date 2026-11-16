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
import io.micronaut.security.scim.core.Group;
import io.micronaut.security.scim.core.ResourceReference;
import io.micronaut.security.scim.data.entities.ScimGroupEntity;
import io.micronaut.security.scim.data.entities.ScimGroupMemberEntity;
import io.micronaut.security.scim.data.entities.ScimResourceType;
import io.micronaut.security.scim.data.jdbc.repositories.ScimGroupJdbcRepository;
import io.micronaut.security.scim.data.jdbc.repositories.ScimGroupMemberJdbcRepository;
import io.micronaut.security.scim.data.jdbc.repositories.ScimResourceExtensionJdbcRepository;
import io.micronaut.security.scim.data.jdbc.repositories.ScimUserJdbcRepository;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.filter.ScimFilterParser;
import io.micronaut.security.scim.server.model.ScimPage;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.model.ScimResourceResponse;
import io.micronaut.security.scim.server.protocol.ScimErrorType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import io.micronaut.security.scim.server.service.ScimGroupService;
import jakarta.inject.Singleton;
import jakarta.transaction.Transactional;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Default blocking {@link ScimGroupService} backed by the SCIM JDBC repositories.
 *
 * @since 5.4.0
 */
@Singleton
@Experimental
@Requires(missingBeans = ScimGroupService.class)
public class DefaultJdbcScimGroupService implements ScimGroupService {
    private static final Argument<Group> GROUP_ARGUMENT = Argument.of(Group.class);

    private final ScimGroupJdbcRepository groupRepository;
    private final ScimUserJdbcRepository userRepository;
    private final ScimGroupMemberJdbcRepository memberRepository;
    private final ScimResourceExtensionJdbcRepository extensionRepository;
    private final ScimResourceIdGenerator idGenerator;
    private final JsonMapper jsonMapper;
    private final ScimFilterParser filterParser;

    /**
     * @param groupRepository Group repository
     * @param userRepository User repository used to validate member references
     * @param memberRepository Group membership repository
     * @param extensionRepository Custom extension repository
     * @param idGenerator Resource identifier generator
     * @param jsonMapper JSON mapper used for extension and PATCH values
     * @param filterParser Parser used for PATCH value-selection filters
     * @since 5.4.0
     */
    public DefaultJdbcScimGroupService(
        ScimGroupJdbcRepository groupRepository,
        ScimUserJdbcRepository userRepository,
        ScimGroupMemberJdbcRepository memberRepository,
        ScimResourceExtensionJdbcRepository extensionRepository,
        ScimResourceIdGenerator idGenerator,
        JsonMapper jsonMapper,
        ScimFilterParser filterParser
    ) {
        this.groupRepository = groupRepository;
        this.userRepository = userRepository;
        this.memberRepository = memberRepository;
        this.extensionRepository = extensionRepository;
        this.idGenerator = idGenerator;
        this.jsonMapper = jsonMapper;
        this.filterParser = filterParser;
    }

    @Override
    @Transactional
    public ScimResourceResponse<Group> create(Group resource, ScimRequestContext context) {
        validate(resource, null);
        String id = idGenerator.generateId(ScimResourceType.GROUP);
        ScimGroupEntity saved = groupRepository.save(toEntity(resource, id, null));
        storeRelated(resource, id);
        return loadResponse(saved, context);
    }

    @Override
    @Transactional
    public Optional<ScimResourceResponse<Group>> get(String id, ScimRequestContext context) {
        return groupRepository.findById(id).map(entity -> loadResponse(entity, context));
    }

    @Override
    @Transactional
    public ScimPage<Group> search(ScimQuery query, ScimRequestContext context) {
        List<Group> groups = new ArrayList<>();
        groupRepository.findAll().forEach(entity -> groups.add(loadResponse(entity, context).resource()));
        return JdbcScimQueryProcessor.process(groups, query);
    }

    @Override
    @Transactional
    public Optional<ScimResourceResponse<Group>> replace(
        String id,
        Group resource,
        ScimRequestContext context
    ) {
        Optional<ScimGroupEntity> existing = groupRepository.findById(id);
        if (existing.isEmpty()) {
            return Optional.empty();
        }
        ScimGroupEntity current = existing.get();
        JdbcScimServiceSupport.verifyIfMatch(context.ifMatch(), current.version());
        validate(resource, id);
        ScimGroupEntity updated = groupRepository.update(toEntity(resource, id, current));
        deleteRelated(id);
        storeRelated(resource, id);
        return Optional.of(loadResponse(updated, context));
    }

    @Override
    @Transactional
    public Optional<ScimResourceResponse<Group>> patch(
        String id,
        ScimPatchRequest patch,
        ScimRequestContext context
    ) {
        Optional<ScimResourceResponse<Group>> existing = get(id, context);
        if (existing.isEmpty()) {
            return Optional.empty();
        }
        Group patched = JdbcScimServiceSupport.applyPatch(
            existing.get().resource(), patch, GROUP_ARGUMENT, jsonMapper, filterParser);
        return replace(id, patched, context);
    }

    @Override
    @Transactional
    public void delete(String id, ScimRequestContext context) {
        ScimGroupEntity existing = groupRepository.findById(id)
            .orElseThrow(() -> new ScimException(HttpStatus.NOT_FOUND, "No SCIM Group exists with id " + id));
        JdbcScimServiceSupport.verifyIfMatch(context.ifMatch(), existing.version());
        deleteRelated(id);
        memberRepository.deleteByMemberIdAndMemberType(id, ScimResourceType.GROUP);
        groupRepository.delete(existing);
    }

    private ScimResourceResponse<Group> loadResponse(ScimGroupEntity entity, ScimRequestContext context) {
        Group group = new Group();
        group.setId(entity.id());
        group.setExternalId(entity.externalId());
        group.setDisplayName(entity.displayName());
        group.setMembers(memberRepository.findAllByGroupIdOrderById(entity.id()).stream()
            .map(member -> toResourceReference(member, context))
            .toList());
        JdbcScimServiceSupport.loadExtensions(
            group, ScimResourceType.GROUP, entity.id(), extensionRepository, jsonMapper);
        return JdbcScimServiceSupport.response(
            group,
            "Group",
            entity.created(),
            entity.lastModified(),
            entity.version(),
            "Groups",
            context
        );
    }

    private ScimGroupEntity toEntity(Group group, String id, @Nullable ScimGroupEntity existing) {
        return new ScimGroupEntity(
            id,
            group.getExternalId(),
            requiredDisplayName(group),
            existing == null ? null : existing.version(),
            existing == null ? null : existing.created(),
            existing == null ? null : existing.lastModified()
        );
    }

    private void storeRelated(Group group, String id) {
        List<ResourceReference> members = group.getMembers();
        if (members != null) {
            Set<String> uniqueMembers = new HashSet<>();
            for (ResourceReference member : members) {
                ScimResourceType type = memberType(member);
                String memberId = requiredMemberId(member);
                if (!exists(type, memberId)) {
                    throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_VALUE,
                        "No " + typeName(type) + " exists with id " + memberId);
                }
                if (!uniqueMembers.add(type + ":" + memberId)) {
                    continue;
                }
                memberRepository.save(new ScimGroupMemberEntity(
                    null,
                    id,
                    memberId,
                    type,
                    member.ref(),
                    member.display()
                ));
            }
        }
        JdbcScimServiceSupport.storeExtensions(
            group, ScimResourceType.GROUP, id, extensionRepository, jsonMapper);
    }

    private void deleteRelated(String id) {
        memberRepository.deleteByGroupId(id);
        extensionRepository.deleteByResourceTypeAndResourceId(ScimResourceType.GROUP, id);
    }

    private ResourceReference toResourceReference(ScimGroupMemberEntity member, ScimRequestContext context) {
        String collection = member.memberType() == ScimResourceType.USER ? "Users" : "Groups";
        String display = member.display();
        if (display == null) {
            display = member.memberType() == ScimResourceType.USER
                ? userRepository.findById(member.memberId()).map(user -> user.displayName() == null
                    ? user.userName() : user.displayName()).orElse(null)
                : groupRepository.findById(member.memberId()).map(ScimGroupEntity::displayName).orElse(null);
        }
        return new ResourceReference(
            member.memberId(),
            member.referenceUri() == null
                ? JdbcScimServiceSupport.location(context, collection, member.memberId()).toString()
                : member.referenceUri(),
            display,
            typeName(member.memberType())
        );
    }

    private boolean exists(ScimResourceType type, String id) {
        return type == ScimResourceType.USER ? userRepository.existsById(id) : groupRepository.existsById(id);
    }

    private static ScimResourceType memberType(ResourceReference member) {
        if (member.type() != null) {
            if (member.type().equalsIgnoreCase("User")) {
                return ScimResourceType.USER;
            }
            if (member.type().equalsIgnoreCase("Group")) {
                return ScimResourceType.GROUP;
            }
            throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_VALUE,
                "Group member type must be User or Group");
        }
        return member.ref() != null && member.ref().contains("/Groups/")
            ? ScimResourceType.GROUP
            : ScimResourceType.USER;
    }

    private static String requiredMemberId(ResourceReference member) {
        if (member.value() == null || member.value().isBlank()) {
            throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_VALUE,
                "Every Group member must have a value");
        }
        return member.value();
    }

    private static String requiredDisplayName(Group group) {
        if (group.getDisplayName() == null || group.getDisplayName().isBlank()) {
            throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_VALUE,
                "displayName must not be blank");
        }
        return group.getDisplayName();
    }

    private void validate(Group group, @Nullable String currentId) {
        String displayName = requiredDisplayName(group);
        boolean duplicate = groupRepository.findAllByDisplayNameIgnoreCase(displayName).stream()
            .anyMatch(existing -> !existing.id().equals(currentId));
        if (duplicate) {
            throw new ScimException(HttpStatus.CONFLICT, ScimErrorType.UNIQUENESS,
                "A Group with displayName " + displayName + " already exists");
        }
    }

    private static String typeName(ScimResourceType type) {
        return type == ScimResourceType.USER ? "User" : "Group";
    }
}
