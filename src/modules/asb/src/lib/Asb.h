// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef ASB_H
#define ASB_H

#ifdef __cplusplus
extern "C"
{
#endif

void AsbInitialize(void);
void AsbShutdown(void);

MMI_HANDLE AsbMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes);
void AsbMmiClose(MMI_HANDLE clientSession);
int AsbMmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes);
int AsbMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes);
int AsbMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes);
void AsbMmiFree(MMI_JSON_STRING payload);

#ifdef __cplusplus
}
#endif

#endif // ASB_H
