//
//  LKKCUtil.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above
//    copyright notice, this list of conditions and the following
//    disclaimer in the documentation and/or other materials provided
//    with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//  
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
//  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL KÁROLY LŐRENTEY BE LIABLE FOR ANY
//  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
//  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 

#define LKKCAssert(condition) NSAssert(condition, @"Assertion failed: %s", #condition)

#define LKKCReportError(status, error, message, ...) LKKCReportErrorImpl(__FILE__, __LINE__, status, error, message, ##__VA_ARGS__)

#define LKKCReportErrorObj(errorIn, errorOut, message, ...) LKKCReportErrorObjImpl(__FILE__, __LINE__, errorIn, errorOut, message, ##__VA_ARGS__) 

void LKKCReportErrorImpl(char *file, int line, OSStatus status, NSError **error, NSString *message, ...) NS_FORMAT_FUNCTION(5, 6);
void LKKCReportErrorObjImpl(char *file, int line, NSError *errorIn, NSError **errorOut, NSString *message, ...) NS_FORMAT_FUNCTION(5, 6);

extern const NSString *const LKKCErrorDomain;