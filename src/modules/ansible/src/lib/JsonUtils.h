// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef JSONUTILS_H
#define JSONUTILS_H

#include <parson.h>

#ifdef __cplusplus
extern "C"
{
#endif

void ConvertObjectArrayPropertyValueToArray(JSON_Value** rootValue, const char* propertyName);
void RemoveObjectsWithPropertyValueNotEqual(JSON_Value* rootValue, const char* propertyName, const char* propertyValue);
void ConvertObjectToKeyValuePairString(const JSON_Value *rootValue, char **buffer);
void ConvertObjectArrayToKeyValuePairString(const JSON_Value *rootValue, char **buffer);

#ifdef __cplusplus
}
#endif

#endif // JSONUTILS_H
