// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef USERS_H
#define USERS_H

#ifdef __cplusplus
extern "C"
{
#endif

void UsersInitialize();
void UsersShutdown(void);

MMI_HANDLE UsersMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes);
void UsersMmiClose(MMI_HANDLE clientSession);
int UsersMmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes);
int UsersMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes);
int UsersMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes);
void UsersMmiFree(MMI_JSON_STRING payload);

#ifdef __cplusplus
}
#endif

#endif // USERS_H
