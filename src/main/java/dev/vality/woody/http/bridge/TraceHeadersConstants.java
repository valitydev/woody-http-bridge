package dev.vality.woody.http.bridge;

import dev.vality.woody.api.trace.context.metadata.user.UserIdentityEmailExtensionKit;
import dev.vality.woody.api.trace.context.metadata.user.UserIdentityIdExtensionKit;
import dev.vality.woody.api.trace.context.metadata.user.UserIdentityRealmExtensionKit;
import dev.vality.woody.api.trace.context.metadata.user.UserIdentityUsernameExtensionKit;
import dev.vality.woody.thrift.impl.http.transport.THttpHeader;

public class TraceHeadersConstants {

    public static final String WOODY_PREFIX = "woody.";
    public static final String WOODY_TRACE_ID = THttpHeader.TRACE_ID.getKey();
    public static final String WOODY_SPAN_ID = THttpHeader.SPAN_ID.getKey();
    public static final String WOODY_PARENT_ID = THttpHeader.PARENT_ID.getKey();
    public static final String WOODY_DEADLINE = THttpHeader.DEADLINE.getKey();
    public static final String WOODY_ERROR_CLASS = THttpHeader.ERROR_CLASS.getKey();
    public static final String WOODY_ERROR_REASON = THttpHeader.ERROR_REASON.getKey();
    public static final String WOODY_META_PREFIX = THttpHeader.META.getKey();
    public static final String WOODY_META_ID = WOODY_META_PREFIX + WoodyMetaHeaders.ID;
    public static final String WOODY_META_USERNAME = WOODY_META_PREFIX + WoodyMetaHeaders.USERNAME;
    public static final String WOODY_META_EMAIL = WOODY_META_PREFIX + WoodyMetaHeaders.EMAIL;
    public static final String WOODY_META_REALM = WOODY_META_PREFIX + WoodyMetaHeaders.REALM;
    public static final String WOODY_META_REQUEST_ID = WOODY_META_PREFIX + WoodyMetaHeaders.X_REQUEST_ID;
    public static final String WOODY_META_REQUEST_DEADLINE =
            WOODY_META_PREFIX + WoodyMetaHeaders.X_REQUEST_DEADLINE;
    public static final String WOODY_META_REQUEST_INVOICE_ID =
            WOODY_META_PREFIX + WoodyMetaHeaders.X_INVOICE_ID;

    public static final String OTEL_TRACE_PARENT = THttpHeader.TRACE_PARENT.getKey();
    public static final String OTEL_TRACE_STATE = THttpHeader.TRACE_STATE.getKey();

    public static final class ExternalHeaders {

        public static final String X_REQUEST_ID = "X-Request-ID";
        public static final String X_REQUEST_DEADLINE = "X-Request-Deadline";
        public static final String X_INVOICE_ID = "X-Invoice-ID";
        public static final String X_WOODY_PREFIX = "x-woody-";
        public static final String X_WOODY_TRACE_ID = X_WOODY_PREFIX + "trace-id";
        public static final String X_WOODY_SPAN_ID = X_WOODY_PREFIX + "span-id";
        public static final String X_WOODY_PARENT_ID = X_WOODY_PREFIX + "parent-id";
        public static final String X_WOODY_DEADLINE = X_WOODY_PREFIX + "deadline";
        public static final String X_WOODY_ERROR_CLASS = X_WOODY_PREFIX + "error-class";
        public static final String X_WOODY_ERROR_REASON = X_WOODY_PREFIX + "error-reason";
        public static final String X_WOODY_META_PREFIX = X_WOODY_PREFIX + "meta-";
        public static final String X_WOODY_META_ID = X_WOODY_META_PREFIX + XWoodyMetaHeaders.ID;
        public static final String X_WOODY_META_USERNAME = X_WOODY_META_PREFIX + XWoodyMetaHeaders.USERNAME;
        public static final String X_WOODY_META_EMAIL = X_WOODY_META_PREFIX + XWoodyMetaHeaders.EMAIL;
        public static final String X_WOODY_META_REALM = X_WOODY_META_PREFIX + XWoodyMetaHeaders.REALM;
        public static final String X_ERROR_CLASS = "X-Error-Class";
        public static final String X_ERROR_REASON = "X-Error-Reason";

        public static final class XWoodyMetaHeaders {

            public static final String USER_IDENTITY_PREFIX = "user-identity-";
            public static final String ID = USER_IDENTITY_PREFIX + "id";
            public static final String USERNAME = USER_IDENTITY_PREFIX + "username";
            public static final String EMAIL = USER_IDENTITY_PREFIX + "email";
            public static final String REALM = USER_IDENTITY_PREFIX + "realm";

        }
    }

    public static final class WoodyMetaHeaders {

        public static final String USER_IDENTITY_PREFIX = "user-identity.";
        public static final String ID = UserIdentityIdExtensionKit.KEY;
        public static final String USERNAME = UserIdentityUsernameExtensionKit.KEY;
        public static final String EMAIL = UserIdentityEmailExtensionKit.KEY;
        public static final String REALM = UserIdentityRealmExtensionKit.KEY;
        public static final String X_REQUEST_ID = USER_IDENTITY_PREFIX + ExternalHeaders.X_REQUEST_ID;
        public static final String X_REQUEST_DEADLINE = USER_IDENTITY_PREFIX + ExternalHeaders.X_REQUEST_DEADLINE;
        public static final String X_INVOICE_ID = USER_IDENTITY_PREFIX + ExternalHeaders.X_INVOICE_ID;

    }
}
