//
//  AESTests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "AESTests.h"

@implementation AESTests

- (void)testAESGeneration
{
    BOOL result;
    
    // Generate a key into a keychain.
    NSData *persistentID = nil;
    NSData *tag = [@"test key tag" dataUsingEncoding:NSUTF8StringEncoding];
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:_keychain];
        should(generator != nil);
        generator.applicationLabel = @"test key ID";
        generator.label = @"test key label";
        generator.tag = tag;
        LKKCKey *key = [generator generateAESKeyWithError:&error];
        should(key != nil);
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, tag);
        
        persistentID = [key.persistentID retain];
        should(persistentID != nil);
        
        result = [key addToKeychain:_keychain error:&error];
        should(!result);
        should([error code] == errSecDuplicateItem);
    }
    
    @autoreleasepool {
        LKKCKey *key = [_keychain keyWithPersistentID:persistentID];
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, tag);
        
        [persistentID release];
        persistentID = nil;
    }
    
    @autoreleasepool {
        NSArray *keys = [_keychain symmetricKeys];
        should([keys count] == 1);
        LKKCKey *key = [keys objectAtIndex:0];
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, tag);
    }
    
    // Generate a floating key.
    NSData *floatingTag = [@"floating key tag" dataUsingEncoding:NSUTF8StringEncoding];
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:nil];
        should(generator != nil);
        generator.applicationLabel = @"floating key ID";
        generator.label = @"floating key label";
        generator.tag = floatingTag;
        LKKCKey *key = [generator generateAESKeyWithError:&error];
        should(key != nil);
        
        should(key.keychain == nil);
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"floating key label");
        shouldBeEqual(key.applicationLabel, @"floating key ID");
        shouldBeEqual(key.tag, floatingTag);
        
        result = [key addToKeychain:_keychain error:&error];
        should(result);
        
        result = [key addToKeychain:_keychain error:&error];
        should(!result);
        should([error code] == errSecDuplicateItem);
        
        persistentID = [key.persistentID retain];
    }
    
    @autoreleasepool {
        LKKCKey *key = [_keychain keyWithPersistentID:persistentID];
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"floating key label");
        shouldBeEqual(key.applicationLabel, @"floating key ID");
        shouldBeEqual(key.tag, floatingTag);
        
        [persistentID release];
        persistentID = nil;
    }
    
    @autoreleasepool {
        // Delete the keys.
        NSError *error = nil;
        NSArray *keys = [_keychain symmetricKeys];
        should([keys count] == 2);
        
        for (LKKCKey *key in keys) {
            result = [key deleteItemWithError:&error];
            should(result);
        }
        
        keys = [_keychain symmetricKeys];
        should([keys count] == 0);
    }
}

- (void)testAESEncryption
{
    NSError *error = nil;
    
    LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:_keychain];
    generator.extractable = NO;
    generator.label = @"AES test key";
    generator.applicationLabel = @"AES test key ID";
    generator.tag = [@"AES test key tag" dataUsingEncoding:NSUTF8StringEncoding];
    
    LKKCKey *key = [generator generateAESKeyWithError:&error];
    should(key != nil);
    
    NSData *iv = [key randomInitVector];
    
    NSString *message = @"This is some sample plaintext";
    NSData *plaintext = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertext = [key encryptData:plaintext initVector:iv error:&error];
    should(ciphertext != nil);
    
    NSData *decryptedtext = [key decryptData:ciphertext initVector:iv error:&error];
    should(decryptedtext != nil);
    shouldBeEqual(decryptedtext, plaintext);
    NSString *decryptedMessage = [[[NSString alloc] initWithData:decryptedtext encoding:NSUTF8StringEncoding] autorelease];
    shouldBeEqual(decryptedMessage, message);
}

- (void)testAESExample
{
    // Sample cipher from Appendix B of FIPS-197 defining the AES
    // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
    NSError *error = nil;
    NSData *plaintext = [NSData dataWithBytes:"\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34" length:16];
    NSData *cipherkey = [NSData dataWithBytes:"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c" length:16];
    NSData *sampleresult = [NSData dataWithBytes:"\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32" length:16];
    NSData *iv = [NSData dataWithBytes:"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" length:16];
    
    LKKCKey *key = [LKKCKey keyWithData:cipherkey keyClass:LKKCKeyClassSymmetric keyType:LKKCKeyTypeAES keySize:128];
    should(key != nil);
    
    
    NSData *ciphertext = [key encryptData:plaintext initVector:iv error:&error];
    should(ciphertext != nil);
    // TODO:
    // The sample result expects no padding, but currently we only support PKCS7.
    // Our result will be different after the first block, but that first block should match.
    shouldBeEqual([ciphertext subdataWithRange:NSMakeRange(0, 16)], sampleresult);
    
    NSData *decryptedtext = [key decryptData:ciphertext initVector:iv error:&error];
    should(decryptedtext != nil);
    shouldBeEqual(decryptedtext, plaintext);
}

@end
