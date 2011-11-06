//
//  LKKCUtil.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#define LKKCAssert(condition) NSAssert(condition, @"Assertion failed: %s", #condition)

#define LKKCReportError(status, error, message, ...) LKKCReportErrorImpl(__FILE__, __LINE__, status, error, message, ##__VA_ARGS__)

#define LKKCReportErrorObj(errorIn, errorOut, message, ...) LKKCReportErrorObjImpl(__FILE__, __LINE__, errorIn, errorOut, message, ##__VA_ARGS__) 

void LKKCReportErrorImpl(char *file, int line, OSStatus status, NSError **error, NSString *message, ...) NS_FORMAT_FUNCTION(5, 6);
void LKKCReportErrorObjImpl(char *file, int line, NSError *errorIn, NSError **errorOut, NSString *message, ...) NS_FORMAT_FUNCTION(5, 6);

extern const NSString *const LKKCErrorDomain;