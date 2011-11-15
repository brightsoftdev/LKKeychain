//
//  LKKeychainTestUtils.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "LKKeychain.h"

@interface LKKeychainTestUtils : NSObject

+ (LKKCKeychain *)createTestKeychain:(NSString *)name;

@end
