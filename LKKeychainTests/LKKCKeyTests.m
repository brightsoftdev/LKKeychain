//
//  LKKCKeyTests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-13.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeyTests.h"
#import "LKKeychain.h"

@implementation LKKCKeyTests
{
    LKKCKeychain *_keychain;
}

- (LKKCKeychain *)createTestKeychain
{
    NSError *error = nil;
    BOOL result;
    
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"Test.keychain"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        LKKCKeychain *oldkeychain = [LKKCKeychain keychainWithPath:path error:&error];
        if (oldkeychain != nil) {
            result = [oldkeychain deleteKeychainWithError:&error];
            should(result);
        }
    }
    LKKCKeychain *keychain = [[LKKCKeychain createKeychainWithPath:path password:@"foobar" error:&error] retain];
    should(keychain != nil);
    
    should(!keychain.locked);
    should(keychain.readable);
    should(keychain.writable);
    return keychain;
}

- (void)setUp
{
    _keychain = [[self createTestKeychain] retain];
}

- (void)tearDown
{
    [_keychain release];
    _keychain = nil;
}

- (void)testAESGeneration
{
    BOOL result;
    
    // Generate a key into a keychain.
    NSData *persistentID = nil;
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:_keychain];
        should(generator != nil);
        generator.applicationLabel = @"test key ID";
        generator.label = @"test key label";
        generator.tag = @"test key tag";
        LKKCKey *key = [generator generateAESKey];
        should(key != nil);
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, @"test key tag");

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
        shouldBeEqual(key.tag, @"test key tag");

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
        shouldBeEqual(key.tag, @"test key tag");
    }
    
    // Generate a floating key.
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:nil];
        should(generator != nil);
        generator.applicationLabel = @"floating key ID";
        generator.label = @"floating key label";
        generator.tag = @"floating key tag";
        LKKCKey *key = [generator generateAESKey];
        should(key != nil);

        should(key.keychain == nil);
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"floating key label");
        shouldBeEqual(key.applicationLabel, @"floating key ID");
        shouldBeEqual(key.tag, @"floating key tag");
        
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
        shouldBeEqual(key.tag, @"floating key tag");
        
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

- (void)test3DESGeneration
{
    BOOL result;
    
    // Generate a key into a keychain.
    NSData *persistentID = nil;
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:_keychain];
        should(generator != nil);
        generator.applicationLabel = @"test key ID";
        generator.label = @"test key label";
        generator.tag = @"test key tag";
        LKKCKey *key = [generator generate3DESKey];
        should(key != nil);
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, @"test key tag");
        
        persistentID = [key.persistentID retain];
        should(persistentID != nil);
        
        result = [key addToKeychain:_keychain error:&error];
        should(!result);
        should([error code] == errSecDuplicateItem);
    }
    
    @autoreleasepool {
        LKKCKey *key = [_keychain keyWithPersistentID:persistentID];
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, @"test key tag");
        
        [persistentID release];
        persistentID = nil;
    }
    
    @autoreleasepool {
        NSArray *keys = [_keychain symmetricKeys];
        should([keys count] == 1);
        LKKCKey *key = [keys objectAtIndex:0];
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, @"test key tag");
    }
    
    // Generate a floating key.
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:nil];
        should(generator != nil);
        generator.applicationLabel = @"floating key ID";
        generator.label = @"floating key label";
        generator.tag = @"floating key tag";
        LKKCKey *key = [generator generate3DESKey];
        should(key != nil);
        
        should(key.keychain == nil);
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
        shouldBeEqual(key.label, @"floating key label");
        shouldBeEqual(key.applicationLabel, @"floating key ID");
        shouldBeEqual(key.tag, @"floating key tag");
        
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
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
        shouldBeEqual(key.label, @"floating key label");
        shouldBeEqual(key.applicationLabel, @"floating key ID");
        shouldBeEqual(key.tag, @"floating key tag");
        
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
    generator.tag = @"AES test key tag";
    LKKCKey *key = [generator generateAESKey];
    should(key != nil);
    
    NSString *message = @"This is some sample plaintext";
    NSData *plaintext = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertext = [key encryptData:plaintext error:&error];
    should(ciphertext != nil);
    
    NSData *decryptedtext = [key decryptData:ciphertext error:&error];
    should(decryptedtext != nil);
    shouldBeEqual(decryptedtext, plaintext);
    NSString *decryptedMessage = [[[NSString alloc] initWithData:decryptedtext encoding:NSUTF8StringEncoding] autorelease];
    shouldBeEqual(decryptedMessage, message);
}

- (void)test3DESEncryption
{
    NSError *error = nil;
    
    LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:_keychain];
    generator.extractable = NO;
    generator.label = @"3DES test key";
    generator.applicationLabel = @"3DES test key ID";
    generator.tag = @"3DES test key tag";
    LKKCKey *key = [generator generate3DESKey];
    should(key != nil);
    
    NSString *message = @"This is some sample plaintext";
    NSData *plaintext = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertext = [key encryptData:plaintext error:&error];
    should(ciphertext != nil);
    
    NSData *decryptedtext = [key decryptData:ciphertext error:&error];
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
    
    LKKCKey *key = [LKKCKey keyWithData:cipherkey keyClass:LKKCKeyClassSymmetric keyType:LKKCKeyTypeAES keySize:128];
    should(key != nil);
    
    NSData *ciphertext = [key encryptData:plaintext error:&error];
    should(ciphertext != nil);
    // TODO:
    // The sample result expects no padding, but currently we only support PKCS7.
    // Our result will be different after the first block, but that first block should match.
    shouldBeEqual([ciphertext subdataWithRange:NSMakeRange(0, 16)], sampleresult);
    
    NSData *decryptedtext = [key decryptData:ciphertext error:&error];
    should(decryptedtext != nil);
    shouldBeEqual(decryptedtext, plaintext);
}

- (void)test3DESExample
{
    // Sample cipher from Appendix B of NIST SP 800-67 defining 3DES.
    // http://csrc.nist.gov/publications/nistpubs/800-67/SP800-67.pdf
    // (Note that the given ASCII plaintext does not match the hexadecimal input that is used in the sample.)
    NSError *error = nil;
    NSData *plaintext = [NSData dataWithBytes:"\x54\x68\x65\x20\x71\x75\x66\x63\x6B\x20\x62\x72\x6F\x77\x6E\x20\x66\x6F\x78\x20\x6A\x75\x6D\x70" length:24];
    NSData *cipherkey = [NSData dataWithBytes:"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01\x45\x67\x89\xAB\xCD\xEF\x01\x23" length:24];
    NSData *sampleresult = [NSData dataWithBytes:"\xA8\x26\xFD\x8C\xE5\x3B\x85\x5F\xCC\xE2\x1C\x81\x12\x25\x6F\xE6\x68\xD5\xC0\x5D\xD9\xB6\xB9\x00" length:24];
    
    LKKCKey *key = [LKKCKey keyWithData:cipherkey keyClass:LKKCKeyClassSymmetric keyType:LKKCKeyType3DES keySize:192];
    should(key != nil);
    
    NSData *ciphertext = [key encryptData:plaintext error:&error];
    should(ciphertext != nil);
    // TODO:
    // The sample result expects no padding and ECB mode, but currently we only support PKCS5 padding and CBC.
    // Our result will be different after the first block, but that first block should match.
    shouldBeEqual([ciphertext subdataWithRange:NSMakeRange(0, 8)], 
                  [sampleresult subdataWithRange:NSMakeRange(0, 8)]);

    NSData *decryptedtext = [key decryptData:ciphertext error:&error];
    should(decryptedtext != nil);
    shouldBeEqual(decryptedtext, plaintext);
}

@end
