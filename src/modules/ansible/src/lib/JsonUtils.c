// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <stdatomic.h>
#include <version.h>
#include <CommonUtils.h>
#include <Logging.h>
#include <Mmi.h>
#include <parson.h>

#include "JsonUtils.h"

void ConvertObjectsWithPropertyNameToArray(JSON_Value** rootValue, const char* propertyName)
{
    JSON_Object* rootObject = NULL;
    JSON_Object* currentObject = NULL;
    JSON_Value* resultValue = json_value_init_array();
    JSON_Array* resultArray = json_value_get_array(resultValue);
    
    size_t i = 0;
    size_t count = 0;

    if (NULL != (rootObject = json_value_get_object(*rootValue)))
    {
        count = json_object_get_count(rootObject);

        for (i = 0; i < count; i++)
        {
            if (NULL != (currentObject = json_object_get_object(rootObject, json_object_get_name(rootObject, i))))
            {
                if (json_object_has_value(currentObject, propertyName))
                {
                    json_array_append_value(resultArray, json_value_deep_copy(json_object_get_value(currentObject, propertyName)));
                }
            }
        }
    }

    if ((NULL != rootValue) && (NULL != *rootValue))
    {
        json_value_free(*rootValue);
    }

    *rootValue = resultValue;
}

void RemoveObjectsWithPropertyValueNotEqual(JSON_Value* rootValue, const char* propertyName, const char* propertyValue)
{
    JSON_Object* rootObject = NULL;
    JSON_Object* currentObject = NULL;

    size_t i = 0;
    size_t count = 0;

    if (NULL != (rootObject = json_value_get_object(rootValue)))
    {
        count = json_object_get_count(rootObject);

        for (i = 0; i < count; i++)
        {
            if (NULL != (currentObject = json_object_get_object(rootObject, json_object_get_name(rootObject, i))))
            {
                if ((!json_object_has_value_of_type(currentObject, propertyName, JSONString)) ||
                    (0 != strcmp(json_object_get_string(currentObject, propertyName), propertyValue)))
                {
                    if (JSONSuccess == json_object_remove(rootObject, json_object_get_name(rootObject, i)))
                    {
                        i--;
                        count--;
                        continue;
                    }
                }
            }
        }
    }
}