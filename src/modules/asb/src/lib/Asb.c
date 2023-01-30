// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <stdatomic.h>
#include <version.h>
#include <CommonUtils.h>
#include <Logging.h>
#include <Mmi.h>
#include <regex.h>

#include "Asb.h"

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

static atomic_int g_referenceCount = 0;
static unsigned int g_maxPayloadSizeBytes = 0;

static const char* g_asbLogFile = "/var/log/osconfig_asb.log";
static const char* g_asbRolledLogFile = "/var/log/osconfig_asb.bak";

static OSCONFIG_LOG_HANDLE g_log = NULL;

static OSCONFIG_LOG_HANDLE AsbGetLog()
{
    return g_log;
}

void AsbInitialize()
{
    g_log = OpenLog(g_asbLogFile, g_asbRolledLogFile);
        
    OsConfigLogInfo(AsbGetLog(), "%s initialized", g_asbModuleName);
}

void AsbShutdown(void)
{
    OsConfigLogInfo(AsbGetLog(), "%s shutting down", g_asbModuleName);

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
    // const char* value = NULL;
    // char* fileContent = NULL;
    // unsigned int fileContentSizeBytes = 0;
    // regmatch_t matchGroups[3] = {0};
    // regex_t permissionRegex = {0};
    // char* currentMatch = NULL;
    // unsigned int currentMatchSizeBytes = 0;

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




        
    //     fileContent = LoadStringFromFile(g_asbConfigFile, false, AsbGetLog());
    //     if (NULL != fileContent)
    //     {
    //         fileContentSizeBytes = strlen(fileContent);
    //         if (0 == regcomp(&permissionRegex, g_permissionConfigPattern, REG_EXTENDED))
    //         {
    //             if (0 == regexec(&permissionRegex, fileContent, 3, matchGroups, 0))
    //             {
    //                 // Property value is located in the third match group.
    //                 if ((IsValidMatchOffsets(matchGroups[0], fileContentSizeBytes)) && 
    //                     (IsValidMatchOffsets(matchGroups[0], fileContentSizeBytes)) && 
    //                     (IsValidMatchOffsets(matchGroups[0], fileContentSizeBytes)))
    //                 {
    //                     currentMatch = fileContent + matchGroups[2].rm_so;
    //                     currentMatchSizeBytes = matchGroups[2].rm_eo - matchGroups[2].rm_so;
                        
    //                     for (unsigned int i = 0; i < g_permissionConfigMapCount; i++)
    //                     {
    //                         if ((currentMatchSizeBytes == strlen(g_permissionConfigMapKeys[i])) && 
    //                             (0 == strncmp(currentMatch, g_permissionConfigMapKeys[i], currentMatchSizeBytes)))
    //                         {
    //                             value = g_permissionConfigMapValues[i];
    //                             break;
    //                         }
    //                     }
    //                 }

    //                 if (NULL == value) 
    //                 {
    //                     if (IsFullLoggingEnabled())
    //                     {
    //                         OsConfigLogError(AsbGetLog(), "MmiGet failed to find valid TOML property '%s'", g_permissionConfigName);
    //                     }
    //                     status = EINVAL;
    //                 }
    //             }
    //             else 
    //             {
    //                 if (IsFullLoggingEnabled())
    //                 {
    //                     OsConfigLogError(AsbGetLog(), "MmiGet failed to find TOML property '%s'", g_permissionConfigName);
    //                 }
    //                 status = EINVAL;
    //             }

    //             regfree(&permissionRegex);
    //         } 
    //         else 
    //         {
    //             OsConfigLogError(AsbGetLog(), "MmiGet failed to compile regular expression '%s'", g_permissionConfigPattern);
    //             status = EINVAL;
    //         }
    //     }
    //     else 
    //     {
    //         if (IsFullLoggingEnabled())
    //         {
    //             OsConfigLogError(AsbGetLog(), "MmiGet failed to read TOML file '%s'", g_asbConfigFile);
    //         }
    //         status = EINVAL;
    //     }

        // if (MMI_OK != status)
        // {
        //     value = g_permissionConfigMapValues[0];
        //     status = MMI_OK;
        // }

        // *payloadSizeBytes = strlen(value);

        // if ((g_maxPayloadSizeBytes > 0) && ((unsigned)*payloadSizeBytes > g_maxPayloadSizeBytes))
        // {
        //     OsConfigLogError(AsbGetLog(), "MmiGet(%s, %s) insufficient maxmimum size (%d bytes) versus data size (%d bytes), reported value will be truncated", componentName, objectName, g_maxPayloadSizeBytes, *payloadSizeBytes);
        //     *payloadSizeBytes = g_maxPayloadSizeBytes;
        // }

        // *payload = (MMI_JSON_STRING)malloc(*payloadSizeBytes);
        // if (NULL != *payload)
        // {
        //     memset(*payload, 0, *payloadSizeBytes);
        //     memcpy(*payload, value, *payloadSizeBytes);
        // }
        // else
        // {
        //     OsConfigLogError(AsbGetLog(), "MmiGet: failed to allocate %d bytes", *payloadSizeBytes + 1);
        //     *payloadSizeBytes = 0;
        //     status = ENOMEM;
        // }
    }

    if (IsFullLoggingEnabled())
    {
        OsConfigLogInfo(AsbGetLog(), "MmiGet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, *payloadSizeBytes, *payload, *payloadSizeBytes, status);
    }

    // FREE_MEMORY(fileContent);

    return status;


    

    // int status = MMI_OK;
    // const char* value = NULL;
    // char* fileContent = NULL;
    // unsigned int fileContentSizeBytes = 0;
    // regmatch_t matchGroups[3] = {0};
    // regex_t permissionRegex = {0};
    // char* currentMatch = NULL;
    // unsigned int currentMatchSizeBytes = 0;

    // if ((NULL == componentName) || (NULL == objectName) || (NULL == payload) || (NULL == payloadSizeBytes))
    // {
    //     OsConfigLogError(AsbGetLog(), "MmiGet(%s, %s, %p, %p) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
    //     status = EINVAL;
    //     return status;
    // }

    // *payload = NULL;
    // *payloadSizeBytes = 0;

    // if (!IsValidSession(clientSession))
    // {
    //     OsConfigLogError(AsbGetLog(), "MmiGet(%s, %s) called outside of a valid session", componentName, objectName);
    //     status = EINVAL;
    // }
    // else if (0 != strcmp(componentName, g_asbComponentName))
    // {
    //     OsConfigLogError(AsbGetLog(), "MmiGet called for an unsupported component name '%s'", componentName);
    //     status = EINVAL;
    // }
    // else if (0 != strcmp(objectName, g_reportedOptInObjectName))
    // {
    //     OsConfigLogError(AsbGetLog(), "MmiGet called for an unsupported object name '%s'", componentName);
    //     status = EINVAL;
    // }
    // else
    // {
    //     fileContent = LoadStringFromFile(g_asbConfigFile, false, AsbGetLog());
    //     if (NULL != fileContent)
    //     {
    //         fileContentSizeBytes = strlen(fileContent);
    //         if (0 == regcomp(&permissionRegex, g_permissionConfigPattern, REG_EXTENDED))
    //         {
    //             if (0 == regexec(&permissionRegex, fileContent, 3, matchGroups, 0))
    //             {
    //                 // Property value is located in the third match group.
    //                 if ((IsValidMatchOffsets(matchGroups[0], fileContentSizeBytes)) && 
    //                     (IsValidMatchOffsets(matchGroups[0], fileContentSizeBytes)) && 
    //                     (IsValidMatchOffsets(matchGroups[0], fileContentSizeBytes)))
    //                 {
    //                     currentMatch = fileContent + matchGroups[2].rm_so;
    //                     currentMatchSizeBytes = matchGroups[2].rm_eo - matchGroups[2].rm_so;
                        
    //                     for (unsigned int i = 0; i < g_permissionConfigMapCount; i++)
    //                     {
    //                         if ((currentMatchSizeBytes == strlen(g_permissionConfigMapKeys[i])) && 
    //                             (0 == strncmp(currentMatch, g_permissionConfigMapKeys[i], currentMatchSizeBytes)))
    //                         {
    //                             value = g_permissionConfigMapValues[i];
    //                             break;
    //                         }
    //                     }
    //                 }

    //                 if (NULL == value) 
    //                 {
    //                     if (IsFullLoggingEnabled())
    //                     {
    //                         OsConfigLogError(AsbGetLog(), "MmiGet failed to find valid TOML property '%s'", g_permissionConfigName);
    //                     }
    //                     status = EINVAL;
    //                 }
    //             }
    //             else 
    //             {
    //                 if (IsFullLoggingEnabled())
    //                 {
    //                     OsConfigLogError(AsbGetLog(), "MmiGet failed to find TOML property '%s'", g_permissionConfigName);
    //                 }
    //                 status = EINVAL;
    //             }

    //             regfree(&permissionRegex);
    //         } 
    //         else 
    //         {
    //             OsConfigLogError(AsbGetLog(), "MmiGet failed to compile regular expression '%s'", g_permissionConfigPattern);
    //             status = EINVAL;
    //         }
    //     }
    //     else 
    //     {
    //         if (IsFullLoggingEnabled())
    //         {
    //             OsConfigLogError(AsbGetLog(), "MmiGet failed to read TOML file '%s'", g_asbConfigFile);
    //         }
    //         status = EINVAL;
    //     }

    //     // Reset status and payload if TOML file could not be parsed or property not found, as it may yet have to be configured.
    //     if (MMI_OK != status)
    //     {
    //         value = g_permissionConfigMapValues[0];
    //         status = MMI_OK;
    //     }

    //     *payloadSizeBytes = strlen(value);

    //     if ((g_maxPayloadSizeBytes > 0) && ((unsigned)*payloadSizeBytes > g_maxPayloadSizeBytes))
    //     {
    //         OsConfigLogError(AsbGetLog(), "MmiGet(%s, %s) insufficient maxmimum size (%d bytes) versus data size (%d bytes), reported value will be truncated", componentName, objectName, g_maxPayloadSizeBytes, *payloadSizeBytes);
    //         *payloadSizeBytes = g_maxPayloadSizeBytes;
    //     }

    //     *payload = (MMI_JSON_STRING)malloc(*payloadSizeBytes);
    //     if (NULL != *payload)
    //     {
    //         memset(*payload, 0, *payloadSizeBytes);
    //         memcpy(*payload, value, *payloadSizeBytes);
    //     }
    //     else
    //     {
    //         OsConfigLogError(AsbGetLog(), "MmiGet: failed to allocate %d bytes", *payloadSizeBytes + 1);
    //         *payloadSizeBytes = 0;
    //         status = ENOMEM;
    //     }
    // }

    // if (IsFullLoggingEnabled())
    // {
    //     OsConfigLogInfo(AsbGetLog(), "MmiGet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, *payloadSizeBytes, *payload, *payloadSizeBytes, status);
    // }

    // FREE_MEMORY(fileContent);

    // return status;
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
