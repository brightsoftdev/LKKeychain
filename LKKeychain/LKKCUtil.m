//
//  LKKCUtil.c
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its contributors 
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.
//  
//  **This software is provided by the copyright holders and contributors "as is" and
//  any express or implied warranties, including, but not limited to, the implied
//  warranties of merchantability and fitness for a particular purpose are
//  disclaimed. In no event shall Károly Lőrentey be liable for any
//  direct, indirect, incidental, special, exemplary, or consequential damages
//  (including, but not limited to, procurement of substitute goods or services;
//  loss of use, data, or profits; or business interruption) however caused and
//  on any theory of liability, whether in contract, strict liability, or tort
//  (including negligence or otherwise) arising in any way out of the use of this
//  software, even if advised of the possibility of such damage.**
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
