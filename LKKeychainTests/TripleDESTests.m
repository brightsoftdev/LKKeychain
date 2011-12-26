//
//  TripleDESTests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "TripleDESTests.h"

@implementation TripleDESTests

- (void)test3DESGeneration
{
    BOOL result;
    
    NSData *tag = [@"test key tag" dataUsingEncoding:NSUTF8StringEncoding];
    
    // Generate a key into a keychain.
    NSData *persistentID = nil;
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:_keychain];
        should(generator != nil);
        generator.applicationLabel = @"test key ID";
        generator.label = @"test key label";
        generator.tag = tag;
        LKKCKey *key = [generator generate3DESKeyWithError:&error];
        should(key != nil);
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
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
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
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
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
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
        LKKCKey *key = [generator generate3DESKeyWithError:&error];
        should(key != nil);
        
        should(key.keychain == nil);
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
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
        should(key.keyType == LKKCKeyType3DES);
        should(key.keySize == 192);
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

- (void)test3DESEncryption
{
    NSError *error = nil;
    
    LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:_keychain];
    generator.extractable = NO;
    generator.label = @"3DES test key";
    generator.applicationLabel = @"3DES test key ID";
    generator.tag = [@"3DES test key tag" dataUsingEncoding:NSUTF8StringEncoding];
    LKKCKey *key = [generator generate3DESKeyWithError:&error];
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

- (void)test3DESExample
{
    // Sample cipher from Appendix B of NIST SP 800-67 defining 3DES.
    // http://csrc.nist.gov/publications/nistpubs/800-67/SP800-67.pdf
    // (Note that the given ASCII plaintext does not match the hexadecimal input that is used in the sample.)
    NSError *error = nil;
    NSData *plaintext = [NSData dataWithBytes:"\x54\x68\x65\x20\x71\x75\x66\x63\x6B\x20\x62\x72\x6F\x77\x6E\x20\x66\x6F\x78\x20\x6A\x75\x6D\x70" length:24];
    NSData *cipherkey = [NSData dataWithBytes:"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01\x45\x67\x89\xAB\xCD\xEF\x01\x23" length:24];
    NSData *sampleresult = [NSData dataWithBytes:"\xA8\x26\xFD\x8C\xE5\x3B\x85\x5F\xCC\xE2\x1C\x81\x12\x25\x6F\xE6\x68\xD5\xC0\x5D\xD9\xB6\xB9\x00" length:24];
    NSData *iv = [NSData dataWithBytes:"\0\0\0\0\0\0\0\0" length:8];
    
    LKKCKey *key = [LKKCKey keyWithData:cipherkey keyClass:LKKCKeyClassSymmetric keyType:LKKCKeyType3DES keySize:192];
    should(key != nil);
    
    NSData *ciphertext = [key encryptData:plaintext initVector:iv error:&error];
    should(ciphertext != nil);
    // TODO:
    // The sample result expects no padding and ECB mode, but currently we only support PKCS5 padding and CBC.
    // Our result will be different after the first block, but that first block should match.
    shouldBeEqual([ciphertext subdataWithRange:NSMakeRange(0, 8)], 
                  [sampleresult subdataWithRange:NSMakeRange(0, 8)]);
    
    NSData *decryptedtext = [key decryptData:ciphertext initVector:iv error:&error];
    should(decryptedtext != nil);
    shouldBeEqual(decryptedtext, plaintext);
}

@end
