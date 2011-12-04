//
//  LKKCIdentity.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
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

#import <LKKeychain/LKKCKeychainItem.h>

@class LKKCCertificate;
@class LKKCKey;

/** Represents an identity. Identities pair certificates with their corresponding private key. */
@interface LKKCIdentity : LKKCKeychainItem

/// The certificate for this identity.
- (LKKCCertificate *)certificate;

/// The private key for this identity.
- (LKKCKey *)privateKey;

/// A human-readable label for the certificate of this identity. (kSecAttrLabel)
@property (nonatomic, readonly) NSString *label;

/// The underlying `SecIdentity` reference.
- (SecIdentityRef)SecIdentity;
@end
