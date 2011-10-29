//
//  LKKCUtil.c
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCUtil.h"

void 
LKKCReportErrorImpl(char *file, int line, OSStatus status, NSString *message, ...)
{
    va_list args;
    va_start(args, message);
    NSString *bakedMessage = [[[NSString alloc] initWithFormat:message arguments:args] autorelease];
    va_end(args);
    CFStringRef errorString = SecCopyErrorMessageString(status, NULL);
    NSLog(@"%s:%d: %@: %@ (%d)", file, line, bakedMessage, (errorString ? (NSString *)errorString : @"unknown error"),  status);
    if (errorString)
        CFRelease(errorString);
}