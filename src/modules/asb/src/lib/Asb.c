// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <stdatomic.h>
#include <version.h>
#include <CommonUtils.h>
#include <Logging.h>
#include <Mmi.h>
#include <regex.h>
#include <parson.h>

#include "Asb.h"

typedef struct ASB_AUDIT_CHECK
{
    char* distro;
    char* command;
    // TODO: ...
} ASB_AUDIT_CHECK;

typedef struct ASB_AUDIT
{
    char* msid;
    char* description;
    size_t checksCount;
    ASB_AUDIT_CHECK* checks;
} ASB_AUDIT;

typedef struct ASB_REMEDIATION_ACTION
{
    char* distro;
    char* action;
    // TODO: ...
} ASB_REMEDIATION_ACTION;

typedef struct ASB_REMEDIATION
{
    char* id;
    size_t msidsCount;
    char** msids;
    char* description;
    size_t actionsCount;
    ASB_REMEDIATION_ACTION* actions;
} ASB_REMEDIATION;

typedef struct ASB_BASELINE
{
    char* baselineId;
    char* baseOrigId;
    // TODO: ...
    size_t auditsCount;
    ASB_AUDIT* audits;
    size_t remediationsCount;
    ASB_REMEDIATION* remediations;
} ASB_BASELINE;

static const char* g_asbModuleInfo = "{\"Name\": \"Asb\","
    "\"Description\": \"Provides functionality to observe and configure Azure Security Baselines\","
    "\"Manufacturer\": \"Microsoft\","
    "\"VersionMajor\": 1,"
    "\"VersionMinor\": 0,"
    "\"VersionInfo\": \"Copper\","
    "\"Components\": [\"Asb\"],"
    "\"Lifetime\": 2,"
    "\"UserAccount\": 0}";

static const char* g_asbModuleName = "Asb module";
static const char* g_asbComponentName = "Asb";

static const char* g_reportedComplianceObjectName = "compliance";
// static const char* g_desiredOptInObjectName = "desiredOptIn";

// static const char* g_asbConfigFileFormat = "Permission = \"%s\"\n";
// static const char* g_permissionConfigPattern = "\\bPermission\\s*=\\s*([\\\"'])([A-Za-z0-9]*)\\1";
// static const char* g_permissionConfigName = "Permission";
// static const char* g_permissionConfigMapKeys[] = {"None", "Required", "Optional"};
// static const char* g_permissionConfigMapValues[] = {"0", "1", "2"};
// static const unsigned int g_permissionConfigMapCount = ARRAY_SIZE(g_permissionConfigMapKeys);

static const char* g_baselineFiles[] = {"/etc/osconfig/asb/asc_audits.json", "/etc/osconfig/asb/cis_audits.json", "/etc/osconfig/asb/common_audits.json", "/etc/osconfig/asb/ssh_audits.json"};
static const unsigned int g_baselinesCount = ARRAY_SIZE(g_baselineFiles);
static ASB_BASELINE* g_baselines[8] = {0}; // TODO: ...

static atomic_int g_referenceCount = 0;
static unsigned int g_maxPayloadSizeBytes = 0;

static const char* g_asbLogFile = "/var/log/osconfig_asb.log";
static const char* g_asbRolledLogFile = "/var/log/osconfig_asb.bak";

static OSCONFIG_LOG_HANDLE g_log = NULL;

static OSCONFIG_LOG_HANDLE AsbGetLog()
{
    return g_log;
}

ASB_BASELINE* AsbLoadBaseline(const char* file)
{
    ASB_BASELINE* baseline = NULL;

    JSON_Value* rootValue = NULL;
    JSON_Object* rootObject = NULL;

    JSON_Array* auditsArray = NULL;
    JSON_Value* auditValue = NULL;
    JSON_Object* auditObject = NULL;

    JSON_Array* checksArray = NULL;;
    JSON_Value* checkValue = NULL;
    JSON_Object* checkObject = NULL;

    JSON_Array* remediationsArray = NULL;

    size_t i = 0;
    size_t j = 0;

    if (NULL != (rootValue = json_parse_file(file)) && (json_value_get_type(rootValue) == JSONObject))
    {
        baseline = (ASB_BASELINE*)malloc(sizeof(ASB_BASELINE));

        if (NULL != baseline)
        {
            baseline->baselineId = NULL;
            baseline->baseOrigId = NULL;
            baseline->auditsCount = 0;
            baseline->audits = NULL;
            baseline->remediationsCount = 0;
            baseline->remediations = NULL;

            rootObject = json_value_get_object(rootValue);
            
            if (json_object_has_value_of_type(rootObject, "@BaselineId", JSONString))
            {
                baseline->baselineId = DuplicateString(json_object_get_string(rootObject, "@BaselineId"));
            }

            if (json_object_has_value_of_type(rootObject, "@BaseOrigId", JSONString))
            {
                baseline->baseOrigId = DuplicateString(json_object_get_string(rootObject, "@BaseOrigId"));
            }

            if (json_object_has_value_of_type(rootObject, "audits", JSONArray))
            {
                auditsArray = json_object_get_array(rootObject, "audits");
                baseline->auditsCount = json_array_get_count(auditsArray);
                baseline->audits = (ASB_AUDIT*)malloc(sizeof(ASB_AUDIT) * baseline->auditsCount);

                if (NULL != baseline->audits)
                {
                    for (i = 0; i < baseline->auditsCount; i++)
                    {
                        baseline->audits[i].msid = NULL;
                        baseline->audits[i].description = NULL;
                        baseline->audits[i].checksCount = 0;
                        baseline->audits[i].checks = NULL;

                        auditValue = json_array_get_value(auditsArray, i);
                
                        if (json_value_get_type(auditValue) == JSONObject)
                        {
                            auditObject = json_value_get_object(auditValue);

                            if (json_object_has_value_of_type(auditObject, "@msid", JSONString))
                            {
                                baseline->audits[i].msid = DuplicateString(json_object_get_string(auditObject, "@msid"));
                            }

                            if (json_object_has_value_of_type(auditObject, "@description", JSONString))
                            {
                                baseline->audits[i].description = DuplicateString(json_object_get_string(auditObject, "@description"));
                            }

                            if (json_object_has_value_of_type(auditObject, "check", JSONArray))
                            {
                                checksArray = json_object_get_array(auditObject, "check");
                                baseline->audits[i].checksCount = json_array_get_count(checksArray);
                                baseline->audits[i].checks = (ASB_AUDIT_CHECK*)malloc(sizeof(ASB_AUDIT_CHECK) * baseline->audits[i].checksCount);

                                if (NULL != baseline->audits[i].checks)
                                {
                                    for (j = 0; j < baseline->audits[i].checksCount; j++)
                                    {
                                        baseline->audits[i].checks[j].distro = NULL;
                                        baseline->audits[i].checks[j].command = NULL;

                                        checkValue = json_array_get_value(checksArray, j);
                                
                                        if (json_value_get_type(checkValue) == JSONObject)
                                        {
                                            checkObject = json_value_get_object(checkValue);

                                            if (json_object_has_value_of_type(checkObject, "@distro", JSONString))
                                            {
                                                baseline->audits[i].checks[j].distro = DuplicateString(json_object_get_string(checkObject, "@distro"));
                                            }

                                            if (json_object_has_value_of_type(checkObject, "@command", JSONString))
                                            {
                                                baseline->audits[i].checks[j].command = DuplicateString(json_object_get_string(checkObject, "@command"));
                                            }
                                        }
                                        else 
                                        {
                                            // LOG: ...
                                        }
                                    }
                                }
                                else 
                                {
                                    // LOG: ...
                                }
                            }
                        }
                        else 
                        {
                            // LOG: ...
                        }
                    }
                }
                else 
                {
                    // LOG: ...
                }
            }

            if (json_object_has_value_of_type(rootObject, "remediations", JSONArray))
            {
                remediationsArray = json_object_get_array(rootObject, "remediations");
                baseline->remediationsCount = json_array_get_count(remediationsArray);

                // TODO: ...
            }
        }
        else 
        {
            // LOG: ...
        }
    }
    else 
    {
        // LOG: ...
    }

    if (NULL != rootValue)
    {
        json_value_free(rootValue);
    }

    return baseline;
}

void AsbFreeBaseline(ASB_BASELINE* baseline)
{
    size_t i = 0;
    size_t j = 0;

    if (NULL != baseline)
    {
        for (i = 0; i < baseline->auditsCount; i++)
        {
            for (j = 0; j < baseline->audits[i].checksCount; j++)
            {
                FREE_MEMORY(baseline->audits[i].checks[j].distro);
                FREE_MEMORY(baseline->audits[i].checks[j].command);
            }

            FREE_MEMORY(baseline->audits[i].msid);
            FREE_MEMORY(baseline->audits[i].description);
            FREE_MEMORY(baseline->audits[i].checks);
        }

        for (i = 0; i < baseline->remediationsCount; i++)
        {
            // TODO: F...
        }

        FREE_MEMORY(baseline->baselineId);
        FREE_MEMORY(baseline->baseOrigId);
        FREE_MEMORY(baseline->audits);
        FREE_MEMORY(baseline->remediations);
    }

    FREE_MEMORY(baseline);
}

void AsbInitialize()
{
    size_t i = 0;

    g_log = OpenLog(g_asbLogFile, g_asbRolledLogFile);

    for (i = 0; i < g_baselinesCount; i++)
    {
        g_baselines[i] = AsbLoadBaseline(g_baselineFiles[i]);

        if (NULL != g_baselines[i])
        {
            OsConfigLogInfo(AsbGetLog(), "AsbInitialize() loaded baseline '%s' (%ld objects) from file '%s'", g_baselines[i]->baselineId, g_baselines[i]->auditsCount + g_baselines[i]->remediationsCount, g_baselineFiles[i]);
        }
        else 
        {
            OsConfigLogInfo(AsbGetLog(), "AsbInitialize() failed to load baseline from file '%s'", g_baselineFiles[i]);
        }
    }

    // ASB_BASELINE* baseline = AsbLoadBaseline("/etc/osconfig/asb/common_audits.json");

    // OsConfigLogInfo(AsbGetLog(), "Baseline: %s %s %ld %ld", baseline->baselineId, baseline->baseOrigId, baseline->auditsCount, baseline->remediationsCount);

    // for (size_t i = 0; i < baseline->auditsCount; i++)
    // {
    //     OsConfigLogInfo(AsbGetLog(), "Audit: %s %ld", baseline->audits[i].msid, baseline->audits[i].checksCount);

    //     for (size_t j = 0; j < baseline->audits[i].checksCount; j++)
    //     {
    //         OsConfigLogInfo(AsbGetLog(), "Check: %s %s", baseline->audits[i].checks[j].distro, baseline->audits[i].checks[j].command);
    //     }
    // }

    OsConfigLogInfo(AsbGetLog(), "%s initialized", g_asbModuleName);
}

void AsbShutdown(void)
{
    size_t i = 0;

    OsConfigLogInfo(AsbGetLog(), "%s shutting down", g_asbModuleName);

    for (i = 0; i < g_baselinesCount; i++)
    {
        AsbFreeBaseline(g_baselines[i]);
    }

    CloseLog(&g_log);
}

MMI_HANDLE AsbMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes)
{
    MMI_HANDLE handle = (MMI_HANDLE)g_asbModuleName;
    g_maxPayloadSizeBytes = maxPayloadSizeBytes;
    ++g_referenceCount;
    OsConfigLogInfo(AsbGetLog(), "MmiOpen(%s, %d) returning %p", clientName, maxPayloadSizeBytes, handle);
    return handle;
}

static bool IsValidSession(MMI_HANDLE clientSession)
{
    return ((NULL == clientSession) || (0 != strcmp(g_asbModuleName, (char*)clientSession)) || (g_referenceCount <= 0)) ? false : true;
}

void AsbMmiClose(MMI_HANDLE clientSession)
{
    if (IsValidSession(clientSession))
    {
        --g_referenceCount;
        OsConfigLogInfo(AsbGetLog(), "MmiClose(%p)", clientSession);
    }
    else 
    {
        OsConfigLogError(AsbGetLog(), "MmiClose() called outside of a valid session");
    }
}

int AsbMmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    int status = EINVAL;

    if ((NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(AsbGetLog(), "MmiGetInfo(%s, %p, %p) called with invalid arguments", clientName, payload, payloadSizeBytes);
        return status;
    }
    
    *payloadSizeBytes = (int)strlen(g_asbModuleInfo);
    *payload = (MMI_JSON_STRING)malloc(*payloadSizeBytes);
    if (*payload)
    {
        memset(*payload, 0, *payloadSizeBytes);
        memcpy(*payload, g_asbModuleInfo, *payloadSizeBytes);
        status = MMI_OK;
    }
    else
    {
        OsConfigLogError(AsbGetLog(), "MmiGetInfo: failed to allocate %d bytes", *payloadSizeBytes);
        *payloadSizeBytes = 0;
        status = ENOMEM;
    }
    
    if (IsFullLoggingEnabled())
    {
        OsConfigLogInfo(AsbGetLog(), "MmiGetInfo(%s, %.*s, %d) returning %d", clientName, *payloadSizeBytes, *payload, *payloadSizeBytes, status);
    }

    return status;
}

int AsbMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    UNUSED(clientSession);
    UNUSED(componentName);
    UNUSED(objectName);
    UNUSED(payload);
    UNUSED(payloadSizeBytes);

    int status = MMI_OK;
    size_t i = 0;
    size_t j = 0;

    if ((NULL == componentName) || (NULL == objectName) || (NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(AsbGetLog(), "MmiGet(%s, %s, %p, %p) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
        status = EINVAL;
        return status;
    }

    *payload = NULL;
    *payloadSizeBytes = 0;

    if (!IsValidSession(clientSession))
    {
        OsConfigLogError(AsbGetLog(), "MmiGet(%s, %s) called outside of a valid session", componentName, objectName);
        status = EINVAL;
    }
    else if (0 != strcmp(componentName, g_asbComponentName))
    {
        OsConfigLogError(AsbGetLog(), "MmiGet called for an unsupported component name '%s'", componentName);
        status = EINVAL;
    }
    else if (0 != strcmp(objectName, g_reportedComplianceObjectName))
    {
        OsConfigLogError(AsbGetLog(), "MmiGet called for an unsupported object name '%s'", objectName);
        status = EINVAL;
    }
    else
    {
        ASB_BASELINE* baseline = g_baselines[2];

        if (NULL != baseline)
        {
            for (i = 0; i < baseline->auditsCount; i++)
            {
                for (j = 0; j < baseline->audits[i].checksCount; j++)
                {
                    if (0 == strcmp("CheckFileExists", baseline->audits[i].checks[j].command))
                    {
                        // TODO: Check!
                        OsConfigLogInfo(AsbGetLog(), "MmiGet called for '%s'", baseline->audits[i].checks[j].command);
                    }
                    else 
                    {

                    }
                }
            }
        }
        else
        {
            // LOG: ...
        }
    }

    if (IsFullLoggingEnabled())
    {
        OsConfigLogInfo(AsbGetLog(), "MmiGet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, *payloadSizeBytes, *payload, *payloadSizeBytes, status);
    }

    return status;
}

int AsbMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes)
{
    OsConfigLogInfo(AsbGetLog(), "No desired objects, MmiSet not implemented");
    
    UNUSED(clientSession);
    UNUSED(componentName);
    UNUSED(objectName);
    UNUSED(payload);
    UNUSED(payloadSizeBytes);
    
    return EPERM;

    // int status = MMI_OK;
    // const char* value = NULL; 
    // char* fileContent = NULL;
    // unsigned int fileContentSizeBytes = 0;

    // if ((NULL == componentName) || (NULL == objectName) || (NULL == payload) || (payloadSizeBytes <= 0))
    // {
    //     OsConfigLogError(AsbGetLog(), "MmiSet(%s, %s, %p, %d) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
    //     status = EINVAL;
    // }
    // else if (!IsValidSession(clientSession))
    // {
    //     OsConfigLogError(AsbGetLog(), "MmiSet(%s, %s) called outside of a valid session", componentName, objectName);
    //     status = EINVAL;
    // }
    // else if (0 != strcmp(componentName, g_asbComponentName))
    // {
    //     OsConfigLogError(AsbGetLog(), "MmiSet called for an unsupported component name '%s'", componentName);
    //     status = EINVAL;
    // }
    // else if (0 != strcmp(objectName, g_desiredOptInObjectName))
    // {
    //     OsConfigLogError(AsbGetLog(), "MmiSet called for an unsupported object name '%s'", objectName);
    //     status = EINVAL;
    // }
    // else if (!IsValidPayload(payload, payloadSizeBytes))
    // {
    //     OsConfigLogError(AsbGetLog(), "MmiSet(%.*s, %d) called with invalid payload", payloadSizeBytes, payload, payloadSizeBytes);
    //     status = EINVAL;
    // }
    // else
    // {
    //     for (unsigned int i = 0; i < g_permissionConfigMapCount; i++)
    //     {
    //         if ((payloadSizeBytes == (int)strlen(g_permissionConfigMapValues[i])) && (0 == strncmp(payload, g_permissionConfigMapValues[i], payloadSizeBytes)))
    //         {
    //             value = g_permissionConfigMapKeys[i];
    //             break;
    //         }
    //     }

    //     if (NULL != value)
    //     {
    //         fileContentSizeBytes = snprintf(NULL, 0, g_asbConfigFileFormat, value);
    //         fileContent = malloc(fileContentSizeBytes + 1);
    //         if (fileContent)
    //         {
    //             memset(fileContent, 0, payloadSizeBytes + 1);
    //             snprintf(fileContent, fileContentSizeBytes + 1, g_asbConfigFileFormat, value);
    //             if (!SavePayloadToFile(g_asbConfigFile, fileContent, fileContentSizeBytes, AsbGetLog()))
    //             {
    //                 OsConfigLogError(AsbGetLog(), "MmiSet failed to write TOML file '%s'", g_asbConfigFile);
    //                 status = EIO;
    //             }

    //             FREE_MEMORY(fileContent);
    //         }
    //         else 
    //         {
    //             OsConfigLogError(AsbGetLog(), "MmiSet: failed to allocate %d bytes", fileContentSizeBytes + 1);
    //             status = ENOMEM;
    //         }
    //     }
    // }

    // OsConfigLogInfo(AsbGetLog(), "MmiSet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, payloadSizeBytes, payload, payloadSizeBytes, status);
    
    // return status;
}

void AsbMmiFree(MMI_JSON_STRING payload)
{
    FREE_MEMORY(payload);
}
