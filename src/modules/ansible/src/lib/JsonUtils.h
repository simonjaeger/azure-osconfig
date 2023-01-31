// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef JSONUTILS_H
#define JSONUTILS_H

#include <parson.h>

#ifdef __cplusplus
extern "C"
{
#endif

void ConvertObjectsWithPropertyNameToArray(JSON_Value** rootValue, const char* propertyName);
void RemoveObjectsWithPropertyValueNotEqual(JSON_Value* rootValue, const char* propertyName, const char* propertyValue);

#ifdef __cplusplus
}
#endif

#endif // JSONUTILS_H
