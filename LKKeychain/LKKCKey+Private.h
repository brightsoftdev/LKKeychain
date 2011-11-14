//
//  LKKCKey+Private.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-14.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKey.h"

@interface LKKCKey (Private)
+ (CFTypeRef)_algorithmFromLKKCKeyType:(LKKCKeyType)keyType;
+ (CSSM_ALGORITHMS)_cssmAlgorithmFromLKKCKeyType:(LKKCKeyType)keyType;
+ (LKKCKeyType)_keyTypeFromAlgorithm:(CFTypeRef)algorithm;
+ (LKKCKeyType)_keyTypeFromCSSMAlgorithm:(CSSM_ALGORITHMS)algorithm;
@end
