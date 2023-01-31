// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <stdatomic.h>
#include <version.h>
#include <CommonUtils.h>
#include <Logging.h>
#include <Mmi.h>
#include <parson.h>

#include "Ansible.h"

#define PYTHON_ENVIRONMENT "/etc/osconfig/python"
#define PYTHON_EXECUTABLE "python3"
#define PYTHON_PIP_DEPENDENCY "pip"
#define PYTHON_VENV_DEPENDENCY "venv"
#define PYTHON_PACKAGE "ansible-core"
#define ANSIBLE_EXECUTABLE "ansible"
#define ANSIBLE_GALAXY_EXECUTABLE "ansible-galaxy"

static const char* g_checkPythonCommand = "which " PYTHON_EXECUTABLE;
static const char* g_checkPythonPipCommand = PYTHON_EXECUTABLE " -m " PYTHON_PIP_DEPENDENCY " --version";
static const char* g_checkPythonVenvCommand = PYTHON_EXECUTABLE " -m " PYTHON_VENV_DEPENDENCY " -h";
static const char* g_checkPythonEnviromentCommand = PYTHON_EXECUTABLE " -m " PYTHON_VENV_DEPENDENCY " " PYTHON_ENVIRONMENT;
static const char* g_checkPythonPackageCommand = "sh -c '. " PYTHON_ENVIRONMENT "/bin/activate; " PYTHON_EXECUTABLE " -m " PYTHON_PIP_DEPENDENCY " install " PYTHON_PACKAGE "'";
static const char* g_checkAnsibleCommand = "sh -c '. " PYTHON_ENVIRONMENT "/bin/activate; which " ANSIBLE_EXECUTABLE "'";
static const char* g_checkAnsibleGalaxyCommand = "sh -c '. " PYTHON_ENVIRONMENT "/bin/activate; which " ANSIBLE_GALAXY_EXECUTABLE "'";

static const char* g_getPythonVersionCommand = "sh -c '. " PYTHON_ENVIRONMENT "/bin/activate; " PYTHON_EXECUTABLE " --version' | grep 'Python ' | cut -d ' ' -f 2 | tr -d '\n'";
static const char* g_getPythonLocationCommand = "sh -c '. " PYTHON_ENVIRONMENT "/bin/activate; which " PYTHON_EXECUTABLE "' | tr -d '\n'";
static const char* g_getAnsibleVersionCommand = "sh -c '. " PYTHON_ENVIRONMENT "/bin/activate; " ANSIBLE_EXECUTABLE " --version' | grep '" ANSIBLE_EXECUTABLE " \\[core ' | cut -d ' ' -f 3 | tr -d ']\n'";
static const char* g_getAnsibleLocationCommand = "sh -c '. " PYTHON_ENVIRONMENT "/bin/activate; which " ANSIBLE_EXECUTABLE "' | tr -d '\n'";
static const char* g_getAnsibleGalaxyLocationCommand = "sh -c '. " PYTHON_ENVIRONMENT "/bin/activate; which " ANSIBLE_GALAXY_EXECUTABLE "' | tr -d '\n'";

// typedef struct MIM_ANSIBLE_DATA_MAPPING
// {
//     const char mimComponentName[64];
//     const char mimObjectName[64];
//     const bool mimDesired;
//     const char ansibleModuleName[64];
//     const char ansibleJsonValuePath[64];
// } MIM_ANSIBLE_DATA_MAPPING;


    // {"Service", "rcctl", false, "ansible.builtin.service_facts", ".ansible_facts.services | map(select(.source==\"rcctl\" and .state==\"running\").name)"},


static const char* g_ansibleModuleInfo = "{\"Name\": \"Ansible\","
    "\"Description\": \"Provides functionality to observe and configure Ansible\","
    "\"Manufacturer\": \"Microsoft\","
    "\"VersionMajor\": 1,"
    "\"VersionMinor\": 0,"
    "\"VersionInfo\": \"Copper\","
    "\"Components\": [\"Ansible\"],"
    "\"Lifetime\": 2,"
    "\"UserAccount\": 0}";

static const char* g_ansibleModuleName = "Ansible module";
// static const char* g_ansibleComponentName = "Ansible";

static atomic_int g_referenceCount = 0;
static unsigned int g_maxPayloadSizeBytes = 0;

static const char* g_ansibleLogFile = "/var/log/osconfig_ansible.log";
static const char* g_ansibleRolledLogFile = "/var/log/osconfig_ansible.bak";

static OSCONFIG_LOG_HANDLE g_log = NULL;
static bool g_enabled = false;

static OSCONFIG_LOG_HANDLE AnsibleGetLog()
{
    return g_log;
}

int AnsibleCheckDependencies(void)
{
    int status = MMI_OK;
    char* pythonVersion = NULL;
    char* pythonLocation = NULL;
    char* ansibleVersion = NULL;
    char* ansibleLocation = NULL;
    char* ansibleGalaxyLocation = NULL;

    if (0 != ExecuteCommand(NULL, g_checkPythonCommand, false, false, 0, 0, NULL, NULL, AnsibleGetLog()))
    {
        if (IsFullLoggingEnabled())
        {
            OsConfigLogError(AnsibleGetLog(), "AnsibleCheckDependencies() cannot find Python executable '%s'", PYTHON_EXECUTABLE);
        }
        status = EINVAL;
    }
    else if (0 != ExecuteCommand(NULL, g_checkPythonPipCommand, false, false, 0, 0, NULL, NULL, AnsibleGetLog()))
    {
        if (IsFullLoggingEnabled())
        {
            OsConfigLogError(AnsibleGetLog(), "AnsibleCheckDependencies() cannot find Python dependency '%s'", PYTHON_PIP_DEPENDENCY);
        }
        status = EINVAL;
    }
    else if (0 != ExecuteCommand(NULL, g_checkPythonVenvCommand, false, false, 0, 0, NULL, NULL, AnsibleGetLog()))
    {
        if (IsFullLoggingEnabled())
        {
            OsConfigLogError(AnsibleGetLog(), "AnsibleCheckDependencies() cannot find Python dependency '%s'", PYTHON_VENV_DEPENDENCY);
        }
        status = EINVAL;
    }
    else if (0 != ExecuteCommand(NULL, g_checkPythonEnviromentCommand, false, false, 0, 0, NULL, NULL, AnsibleGetLog()))
    {
        if (IsFullLoggingEnabled())
        {
            OsConfigLogError(AnsibleGetLog(), "AnsibleCheckDependencies() cannot find Python environment '%s'", PYTHON_ENVIRONMENT);
        }
        status = EINVAL;
    }
    else if (0 != ExecuteCommand(NULL, g_checkPythonPackageCommand, false, false, 0, 0, NULL, NULL, AnsibleGetLog()))
    {
        if (IsFullLoggingEnabled())
        {
            OsConfigLogError(AnsibleGetLog(), "AnsibleCheckDependencies() cannot find Python package '%s'", PYTHON_PACKAGE);
        }
        status = EINVAL;
    }
    else if (0 != ExecuteCommand(NULL, g_checkAnsibleCommand, false, false, 0, 0, NULL, NULL, AnsibleGetLog()))
    {
        if (IsFullLoggingEnabled())
        {
            OsConfigLogError(AnsibleGetLog(), "AnsibleCheckDependencies() cannot find Ansible executable '%s'", ANSIBLE_EXECUTABLE);
        }
        status = EINVAL;
    }
    else if (0 != ExecuteCommand(NULL, g_checkAnsibleGalaxyCommand, false, false, 0, 0, NULL, NULL, AnsibleGetLog()))
    {
        if (IsFullLoggingEnabled())
        {
            OsConfigLogError(AnsibleGetLog(), "AnsibleCheckDependencies() cannot find Ansible executable '%s'", ANSIBLE_GALAXY_EXECUTABLE);
        }
        status = EINVAL;
    }
    else if ((0 != ExecuteCommand(NULL, g_getPythonVersionCommand, false, false, 0, 0, &pythonVersion, NULL, AnsibleGetLog())) ||
        (0 != ExecuteCommand(NULL, g_getPythonLocationCommand, false, false, 0, 0, &pythonLocation, NULL, AnsibleGetLog())) ||
        (0 != ExecuteCommand(NULL, g_getAnsibleVersionCommand, false, false, 0, 0, &ansibleVersion, NULL, AnsibleGetLog())) ||
        (0 != ExecuteCommand(NULL, g_getAnsibleLocationCommand, false, false, 0, 0, &ansibleLocation, NULL, AnsibleGetLog())) || 
        (0 != ExecuteCommand(NULL, g_getAnsibleGalaxyLocationCommand, false, false, 0, 0, &ansibleGalaxyLocation, NULL, AnsibleGetLog())))
    {
        if (IsFullLoggingEnabled())
        {
            OsConfigLogError(AnsibleGetLog(), "AnsibleCheckDependencies() cannot find dependency information");
        }
        status = EINVAL;
    }
    else
    {
        if (IsFullLoggingEnabled())
        {
            OsConfigLogInfo(AnsibleGetLog(), "AnsibleCheckDependencies() found Python executable ('%s', '%s')", pythonVersion, pythonLocation);
            OsConfigLogInfo(AnsibleGetLog(), "AnsibleCheckDependencies() found Ansible executables ('%s', '%s', '%s')", ansibleVersion, ansibleLocation, ansibleGalaxyLocation);
        }
    }

    FREE_MEMORY(pythonVersion);
    FREE_MEMORY(pythonLocation);
    FREE_MEMORY(ansibleVersion);
    FREE_MEMORY(ansibleLocation);
    FREE_MEMORY(ansibleGalaxyLocation);

    return status;
}

void AnsibleInitialize()
{
    g_log = OpenLog(g_ansibleLogFile, g_ansibleRolledLogFile);
    g_enabled = (MMI_OK == AnsibleCheckDependencies());

    OsConfigLogInfo(AnsibleGetLog(), "%s initialized", g_ansibleModuleName);
}

void AnsibleShutdown(void)
{
    OsConfigLogInfo(AnsibleGetLog(), "%s shutting down", g_ansibleModuleName);

    CloseLog(&g_log);
}

MMI_HANDLE AnsibleMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes)
{
    MMI_HANDLE handle = (MMI_HANDLE)g_ansibleModuleName;
    g_maxPayloadSizeBytes = maxPayloadSizeBytes;
    ++g_referenceCount;
    OsConfigLogInfo(AnsibleGetLog(), "MmiOpen(%s, %d) returning %p", clientName, maxPayloadSizeBytes, handle);
    return handle;
}

static bool IsValidSession(MMI_HANDLE clientSession)
{
    return ((NULL == clientSession) || (0 != strcmp(g_ansibleModuleName, (char*)clientSession)) || (g_referenceCount <= 0)) ? false : true;
}

void AnsibleMmiClose(MMI_HANDLE clientSession)
{
    if (IsValidSession(clientSession))
    {
        --g_referenceCount;
        OsConfigLogInfo(AnsibleGetLog(), "MmiClose(%p)", clientSession);
    }
    else 
    {
        OsConfigLogError(AnsibleGetLog(), "MmiClose() called outside of a valid session");
    }
}

int AnsibleMmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    int status = EINVAL;

    if ((NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGetInfo(%s, %p, %p) called with invalid arguments", clientName, payload, payloadSizeBytes);
        return status;
    }
    
    *payloadSizeBytes = (int)strlen(g_ansibleModuleInfo);
    *payload = (MMI_JSON_STRING)malloc(*payloadSizeBytes);
    if (*payload)
    {
        memset(*payload, 0, *payloadSizeBytes);
        memcpy(*payload, g_ansibleModuleInfo, *payloadSizeBytes);
        status = MMI_OK;
    }
    else
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGetInfo: failed to allocate %d bytes", *payloadSizeBytes);
        *payloadSizeBytes = 0;
        status = ENOMEM;
    }
    
    if (IsFullLoggingEnabled())
    {
        OsConfigLogInfo(AnsibleGetLog(), "MmiGetInfo(%s, %.*s, %d) returning %d", clientName, *payloadSizeBytes, *payload, *payloadSizeBytes, status);
    }

    return status;
}

int AnsibleMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    OsConfigLogInfo(AnsibleGetLog(), "No reported objects, MmiGet not implemented");

    // json_dot
    
    UNUSED(clientSession);
    UNUSED(componentName);
    UNUSED(objectName);
    UNUSED(payload);
    UNUSED(payloadSizeBytes);
    
    return EPERM;
}

int AnsibleMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes)
{
    OsConfigLogInfo(AnsibleGetLog(), "No desired objects, MmiSet not implemented");
    
    UNUSED(clientSession);
    UNUSED(componentName);
    UNUSED(objectName);
    UNUSED(payload);
    UNUSED(payloadSizeBytes);
    
    return EPERM;
}

void AnsibleMmiFree(MMI_JSON_STRING payload)
{
    FREE_MEMORY(payload);
}
