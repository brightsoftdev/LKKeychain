//
//  LKKCIdentity.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainItem.h"

@class LKKCCertificate;
@class LKKCKey;
@interface LKKCIdentity : LKKCKeychainItem

- (LKKCCertificate *)certificate;
- (LKKCKey *)privateKey;

@property (nonatomic, readonly) NSString *label; // kSecAttrLabel

- (SecIdentityRef)SecIdentity;
@end
