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
package io.micronaut.security.csp.conf;

import io.micronaut.security.csp.conf.baseuri.BaseUriConfiguration;
import io.micronaut.security.csp.conf.baseuri.BaseUriConfigurationProperties;
import io.micronaut.security.csp.conf.connectsrc.ConnectSrcConfiguration;
import io.micronaut.security.csp.conf.connectsrc.ConnectSrcConfigurationProperties;
import io.micronaut.security.csp.conf.defaultsrc.DefaultSrcConfiguration;
import io.micronaut.security.csp.conf.defaultsrc.DefaultSrcConfigurationProperties;
import io.micronaut.security.csp.conf.fencedframesrc.FencedFrameSrcConfiguration;
import io.micronaut.security.csp.conf.fencedframesrc.FencedFrameSrcConfigurationProperties;
import io.micronaut.security.csp.conf.fontsrc.FontSrcConfiguration;
import io.micronaut.security.csp.conf.fontsrc.FontSrcConfigurationProperties;
import io.micronaut.security.csp.conf.formaction.FormActionConfiguration;
import io.micronaut.security.csp.conf.formaction.FormActionConfigurationProperties;
import io.micronaut.security.csp.conf.frameancestors.FrameAncestorsConfiguration;
import io.micronaut.security.csp.conf.frameancestors.FrameAncestorsConfigurationProperties;
import io.micronaut.security.csp.conf.framesrc.FrameSrcConfiguration;
import io.micronaut.security.csp.conf.framesrc.FrameSrcConfigurationProperties;
import io.micronaut.security.csp.conf.imgsrc.ImgSrcConfiguration;
import io.micronaut.security.csp.conf.imgsrc.ImgSrcConfigurationProperties;
import io.micronaut.security.csp.conf.manifestsrc.ManifestSrcConfiguration;
import io.micronaut.security.csp.conf.manifestsrc.ManifestSrcConfigurationProperties;
import io.micronaut.security.csp.conf.mediasrc.MediaSrcConfiguration;
import io.micronaut.security.csp.conf.mediasrc.MediaSrcConfigurationProperties;
import io.micronaut.security.csp.conf.objectsrc.ObjectSrcConfiguration;
import io.micronaut.security.csp.conf.objectsrc.ObjectSrcConfigurationProperties;
import io.micronaut.security.csp.conf.prefetchsrc.PrefetchSrcConfiguration;
import io.micronaut.security.csp.conf.prefetchsrc.PrefetchSrcConfigurationProperties;
import io.micronaut.security.csp.conf.reportto.ReportToConfiguration;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfiguration;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfigurationProperties;
import io.micronaut.security.csp.conf.stylesrc.StyleSrcConfiguration;
import io.micronaut.security.csp.conf.stylesrc.StyleSrcConfigurationProperties;
import io.micronaut.security.csp.conf.workersrc.WorkerSrcConfiguration;
import io.micronaut.security.csp.conf.workersrc.WorkerSrcConfigurationProperties;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * The configuration of every Content Security Policy directive that has its own configuration
 * contract. It lets a policy generator receive all of them as one dependency, so that a new
 * directive does not change the constructor of the generator or of its subclasses.
 *
 * <p>The bean holds the configuration bound from the application's properties. Use
 * {@link #builder()} to create an instance by hand, for example in a test.</p>
 *
 * @since 5.6.0
 */
@Singleton
public final class ContentSecurityPolicyDirectiveConfigurations {
    private final BaseUriConfiguration baseUri;
    private final DefaultSrcConfiguration defaultSrc;
    private final ConnectSrcConfiguration connectSrc;
    private final FencedFrameSrcConfiguration fencedFrameSrc;
    private final FontSrcConfiguration fontSrc;
    private final ObjectSrcConfiguration objectSrc;
    private final PrefetchSrcConfiguration prefetchSrc;
    private final ReportToConfiguration reportTo;
    private final ScriptSrcConfiguration scriptSrc;
    private final FrameAncestorsConfiguration frameAncestors;
    private final FrameSrcConfiguration frameSrc;
    private final ImgSrcConfiguration imgSrc;
    private final ManifestSrcConfiguration manifestSrc;
    private final MediaSrcConfiguration mediaSrc;
    private final FormActionConfiguration formAction;
    private final StyleSrcConfiguration styleSrc;
    private final WorkerSrcConfiguration workerSrc;

    /**
     * Creates the holder from the directive configuration beans.
     *
     * @param baseUri configures {@code base-uri}
     * @param defaultSrc configures {@code default-src}
     * @param connectSrc configures {@code connect-src}
     * @param fencedFrameSrc configures {@code fenced-frame-src}
     * @param fontSrc configures {@code font-src}
     * @param objectSrc configures {@code object-src}
     * @param prefetchSrc configures {@code prefetch-src}
     * @param reportTo configures {@code report-to}
     * @param scriptSrc configures {@code script-src}
     * @param frameAncestors configures {@code frame-ancestors}
     * @param frameSrc configures {@code frame-src}
     * @param imgSrc configures {@code img-src}
     * @param manifestSrc configures {@code manifest-src}
     * @param mediaSrc configures {@code media-src}
     * @param formAction configures {@code form-action}
     * @param styleSrc configures {@code style-src}
     * @param workerSrc configures {@code worker-src}
     */
    @SuppressWarnings("ParameterNumber")
    @Inject
    ContentSecurityPolicyDirectiveConfigurations(BaseUriConfiguration baseUri,
                                                 DefaultSrcConfiguration defaultSrc,
                                                 ConnectSrcConfiguration connectSrc,
                                                 FencedFrameSrcConfiguration fencedFrameSrc,
                                                 FontSrcConfiguration fontSrc,
                                                 ObjectSrcConfiguration objectSrc,
                                                 PrefetchSrcConfiguration prefetchSrc,
                                                 ReportToConfiguration reportTo,
                                                 ScriptSrcConfiguration scriptSrc,
                                                 FrameAncestorsConfiguration frameAncestors,
                                                 FrameSrcConfiguration frameSrc,
                                                 ImgSrcConfiguration imgSrc,
                                                 ManifestSrcConfiguration manifestSrc,
                                                 MediaSrcConfiguration mediaSrc,
                                                 FormActionConfiguration formAction,
                                                 StyleSrcConfiguration styleSrc,
                                                 WorkerSrcConfiguration workerSrc) {
        this.baseUri = baseUri;
        this.defaultSrc = defaultSrc;
        this.connectSrc = connectSrc;
        this.fencedFrameSrc = fencedFrameSrc;
        this.fontSrc = fontSrc;
        this.objectSrc = objectSrc;
        this.prefetchSrc = prefetchSrc;
        this.reportTo = reportTo;
        this.scriptSrc = scriptSrc;
        this.frameAncestors = frameAncestors;
        this.frameSrc = frameSrc;
        this.imgSrc = imgSrc;
        this.manifestSrc = manifestSrc;
        this.mediaSrc = mediaSrc;
        this.formAction = formAction;
        this.styleSrc = styleSrc;
        this.workerSrc = workerSrc;
    }

    /**
     * Creates a builder whose directives start with their default configuration.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the configuration of the {@code base-uri} directive.
     *
     * @return the {@code base-uri} configuration
     */
    public BaseUriConfiguration getBaseUri() {
        return baseUri;
    }

    /**
     * Returns the configuration of the {@code default-src} directive.
     *
     * @return the {@code default-src} configuration
     */
    public DefaultSrcConfiguration getDefaultSrc() {
        return defaultSrc;
    }

    /**
     * Returns the configuration of the {@code connect-src} directive.
     *
     * @return the {@code connect-src} configuration
     */
    public ConnectSrcConfiguration getConnectSrc() {
        return connectSrc;
    }

    /**
     * Returns the configuration of the {@code fenced-frame-src} directive.
     *
     * @return the {@code fenced-frame-src} configuration
     */
    public FencedFrameSrcConfiguration getFencedFrameSrc() {
        return fencedFrameSrc;
    }

    /**
     * Returns the configuration of the {@code font-src} directive.
     *
     * @return the {@code font-src} configuration
     */
    public FontSrcConfiguration getFontSrc() {
        return fontSrc;
    }

    /**
     * Returns the configuration of the {@code object-src} directive.
     *
     * @return the {@code object-src} configuration
     */
    public ObjectSrcConfiguration getObjectSrc() {
        return objectSrc;
    }

    /**
     * Returns the configuration of the {@code prefetch-src} directive.
     *
     * @return the {@code prefetch-src} configuration
     */
    public PrefetchSrcConfiguration getPrefetchSrc() {
        return prefetchSrc;
    }

    /**
     * Returns the configuration of the {@code report-to} directive.
     *
     * @return the {@code report-to} configuration
     */
    public ReportToConfiguration getReportTo() {
        return reportTo;
    }

    /**
     * Returns the configuration of the {@code script-src} directive.
     *
     * @return the {@code script-src} configuration
     */
    public ScriptSrcConfiguration getScriptSrc() {
        return scriptSrc;
    }

    /**
     * Returns the configuration of the {@code frame-ancestors} directive.
     *
     * @return the {@code frame-ancestors} configuration
     */
    public FrameAncestorsConfiguration getFrameAncestors() {
        return frameAncestors;
    }

    /**
     * Returns the configuration of the {@code frame-src} directive.
     *
     * @return the {@code frame-src} configuration
     */
    public FrameSrcConfiguration getFrameSrc() {
        return frameSrc;
    }

    /**
     * Returns the configuration of the {@code img-src} directive.
     *
     * @return the {@code img-src} configuration
     */
    public ImgSrcConfiguration getImgSrc() {
        return imgSrc;
    }

    /**
     * Returns the configuration of the {@code manifest-src} directive.
     *
     * @return the {@code manifest-src} configuration
     */
    public ManifestSrcConfiguration getManifestSrc() {
        return manifestSrc;
    }

    /**
     * Returns the configuration of the {@code media-src} directive.
     *
     * @return the {@code media-src} configuration
     */
    public MediaSrcConfiguration getMediaSrc() {
        return mediaSrc;
    }

    /**
     * Returns the configuration of the {@code form-action} directive.
     *
     * @return the {@code form-action} configuration
     */
    public FormActionConfiguration getFormAction() {
        return formAction;
    }

    /**
     * Returns the configuration of the {@code style-src} directive.
     *
     * @return the {@code style-src} configuration
     */
    public StyleSrcConfiguration getStyleSrc() {
        return styleSrc;
    }

    /**
     * Returns the configuration of the {@code worker-src} directive.
     *
     * @return the {@code worker-src} configuration
     */
    public WorkerSrcConfiguration getWorkerSrc() {
        return workerSrc;
    }

    /**
     * Builds a {@link ContentSecurityPolicyDirectiveConfigurations}. A directive that is not set
     * keeps its default configuration.
     *
     * @since 5.6.0
     */
    public static final class Builder {
        private BaseUriConfiguration baseUri = new BaseUriConfigurationProperties();
        private DefaultSrcConfiguration defaultSrc = new DefaultSrcConfigurationProperties();
        private ConnectSrcConfiguration connectSrc = new ConnectSrcConfigurationProperties();
        private FencedFrameSrcConfiguration fencedFrameSrc = new FencedFrameSrcConfigurationProperties();
        private FontSrcConfiguration fontSrc = new FontSrcConfigurationProperties();
        private ObjectSrcConfiguration objectSrc = new ObjectSrcConfigurationProperties();
        private PrefetchSrcConfiguration prefetchSrc = new PrefetchSrcConfigurationProperties();
        private ReportToConfiguration reportTo = new ReportToConfigurationProperties();
        private ScriptSrcConfiguration scriptSrc = new ScriptSrcConfigurationProperties();
        private FrameAncestorsConfiguration frameAncestors = new FrameAncestorsConfigurationProperties();
        private FrameSrcConfiguration frameSrc = new FrameSrcConfigurationProperties();
        private ImgSrcConfiguration imgSrc = new ImgSrcConfigurationProperties();
        private ManifestSrcConfiguration manifestSrc = new ManifestSrcConfigurationProperties();
        private MediaSrcConfiguration mediaSrc = new MediaSrcConfigurationProperties();
        private FormActionConfiguration formAction = new FormActionConfigurationProperties();
        private StyleSrcConfiguration styleSrc = new StyleSrcConfigurationProperties();
        private WorkerSrcConfiguration workerSrc = new WorkerSrcConfigurationProperties();

        private Builder() {
        }

        /**
         * Sets the configuration of the {@code base-uri} directive.
         *
         * @param baseUri the {@code base-uri} configuration
         * @return this builder
         */
        public Builder baseUri(BaseUriConfiguration baseUri) {
            this.baseUri = baseUri;
            return this;
        }

        /**
         * Sets the configuration of the {@code default-src} directive.
         *
         * @param defaultSrc the {@code default-src} configuration
         * @return this builder
         */
        public Builder defaultSrc(DefaultSrcConfiguration defaultSrc) {
            this.defaultSrc = defaultSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code connect-src} directive.
         *
         * @param connectSrc the {@code connect-src} configuration
         * @return this builder
         */
        public Builder connectSrc(ConnectSrcConfiguration connectSrc) {
            this.connectSrc = connectSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code fenced-frame-src} directive.
         *
         * @param fencedFrameSrc the {@code fenced-frame-src} configuration
         * @return this builder
         */
        public Builder fencedFrameSrc(FencedFrameSrcConfiguration fencedFrameSrc) {
            this.fencedFrameSrc = fencedFrameSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code font-src} directive.
         *
         * @param fontSrc the {@code font-src} configuration
         * @return this builder
         */
        public Builder fontSrc(FontSrcConfiguration fontSrc) {
            this.fontSrc = fontSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code object-src} directive.
         *
         * @param objectSrc the {@code object-src} configuration
         * @return this builder
         */
        public Builder objectSrc(ObjectSrcConfiguration objectSrc) {
            this.objectSrc = objectSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code prefetch-src} directive.
         *
         * @param prefetchSrc the {@code prefetch-src} configuration
         * @return this builder
         */
        public Builder prefetchSrc(PrefetchSrcConfiguration prefetchSrc) {
            this.prefetchSrc = prefetchSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code report-to} directive.
         *
         * @param reportTo the {@code report-to} configuration
         * @return this builder
         */
        public Builder reportTo(ReportToConfiguration reportTo) {
            this.reportTo = reportTo;
            return this;
        }

        /**
         * Sets the configuration of the {@code script-src} directive.
         *
         * @param scriptSrc the {@code script-src} configuration
         * @return this builder
         */
        public Builder scriptSrc(ScriptSrcConfiguration scriptSrc) {
            this.scriptSrc = scriptSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code frame-ancestors} directive.
         *
         * @param frameAncestors the {@code frame-ancestors} configuration
         * @return this builder
         */
        public Builder frameAncestors(FrameAncestorsConfiguration frameAncestors) {
            this.frameAncestors = frameAncestors;
            return this;
        }

        /**
         * Sets the configuration of the {@code frame-src} directive.
         *
         * @param frameSrc the {@code frame-src} configuration
         * @return this builder
         */
        public Builder frameSrc(FrameSrcConfiguration frameSrc) {
            this.frameSrc = frameSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code img-src} directive.
         *
         * @param imgSrc the {@code img-src} configuration
         * @return this builder
         */
        public Builder imgSrc(ImgSrcConfiguration imgSrc) {
            this.imgSrc = imgSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code manifest-src} directive.
         *
         * @param manifestSrc the {@code manifest-src} configuration
         * @return this builder
         */
        public Builder manifestSrc(ManifestSrcConfiguration manifestSrc) {
            this.manifestSrc = manifestSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code media-src} directive.
         *
         * @param mediaSrc the {@code media-src} configuration
         * @return this builder
         */
        public Builder mediaSrc(MediaSrcConfiguration mediaSrc) {
            this.mediaSrc = mediaSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code form-action} directive.
         *
         * @param formAction the {@code form-action} configuration
         * @return this builder
         */
        public Builder formAction(FormActionConfiguration formAction) {
            this.formAction = formAction;
            return this;
        }

        /**
         * Sets the configuration of the {@code style-src} directive.
         *
         * @param styleSrc the {@code style-src} configuration
         * @return this builder
         */
        public Builder styleSrc(StyleSrcConfiguration styleSrc) {
            this.styleSrc = styleSrc;
            return this;
        }

        /**
         * Sets the configuration of the {@code worker-src} directive.
         *
         * @param workerSrc the {@code worker-src} configuration
         * @return this builder
         */
        public Builder workerSrc(WorkerSrcConfiguration workerSrc) {
            this.workerSrc = workerSrc;
            return this;
        }

        /**
         * Builds the holder.
         *
         * @return the directive configurations
         */
        public ContentSecurityPolicyDirectiveConfigurations build() {
            return new ContentSecurityPolicyDirectiveConfigurations(
                baseUri, defaultSrc, connectSrc, fencedFrameSrc, fontSrc, objectSrc, prefetchSrc, reportTo, scriptSrc,
                frameAncestors, frameSrc, imgSrc, manifestSrc, mediaSrc, formAction, styleSrc, workerSrc);
        }
    }
}
