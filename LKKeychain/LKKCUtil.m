//
//  LKKCUtil.c
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCUtil.h"

NSString *const LKKCErrorDomain = @"LKKeychain";

void 
LKKCReportErrorImpl(char *file, int line, OSStatus status, NSError **error, NSString *message, ...)
{
    va_list args;
    va_start(args, message);
    NSString *bakedMessage = [[[NSString alloc] initWithFormat:message arguments:args] autorelease];
    va_end(args);
    CFStringRef errorString = SecCopyErrorMessageString(status, NULL);
    NSLog(@"%s:%d: %@: %@ (%d)", file, line, bakedMessage, (errorString ? (NSString *)errorString : @"unknown error"),  (int)status);
    if (error != NULL) {
        *error = [NSError errorWithDomain:LKKCErrorDomain 
                                     code:status 
                                 userInfo:[NSDictionary dictionaryWithObjectsAndKeys:
                                           (id)errorString, NSLocalizedDescriptionKey,
                                           nil]];
    }
    if (errorString)
        CFRelease(errorString);
}

void 
LKKCReportErrorObjImpl(char *file, int line, NSError *errorIn, NSError **errorOut, NSString *message, ...)
{
    va_list args;
    va_start(args, message);
    NSString *bakedMessage = [[[NSString alloc] initWithFormat:message arguments:args] autorelease];
    va_end(args);
    NSLog(@"%s:%d: %@: %@ (%@ %d)", file, line, bakedMessage, [errorIn localizedDescription], [errorIn domain], (int)[errorIn code]);
    if (errorOut != NULL) {
        *errorOut = errorIn;
    }
}
