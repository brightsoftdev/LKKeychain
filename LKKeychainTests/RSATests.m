//
//  RSATests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "RSATests.h"
#import <CommonCrypto/CommonDigest.h>

@implementation RSATests

- (void)testRSAGeneration
{
    BOOL result;
    
    // Generate a keypair into a keychain.
    NSData *publicID = nil;
    NSData *privateID = nil;
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:_keychain];
        should(generator != nil);
        generator.label = @"test RSA key label";
        generator.tag = @"test RSA key tag";
        LKKCKeyPair *keypair = [generator generateRSAKeyPair];
        should(keypair != nil);
        
        LKKCKey *publicKey = keypair.publicKey;
        LKKCKey *privateKey = keypair.privateKey;
        
        should(publicKey.keyClass == LKKCKeyClassPublic);
        should(privateKey.keyClass == LKKCKeyClassPrivate);
        should(publicKey.keyType == LKKCKeyTypeRSA);
        should(privateKey.keyType == LKKCKeyTypeRSA);
        should(publicKey.keySize == 2048);
        should(privateKey.keySize == 2048);
        shouldBeEqual(publicKey.label, @"test RSA key label");
        shouldBeEqual(privateKey.label, @"test RSA key label");
        shouldBeEqual(publicKey.tag, @"test RSA key tag");
        shouldBeEqual(privateKey.tag, @"test RSA key tag");
        
        should(publicKey.keyID != nil);
        shouldBeEqual(publicKey.keyID, privateKey.keyID);

        publicID = [[publicKey persistentID] retain];
        privateID = [[privateKey persistentID] retain];
        should(publicID != nil);
        should(privateID != nil);
        
        result = [publicKey addToKeychain:_keychain error:&error];
        should(!result);
        should([error code] == errSecDuplicateItem);
        
        result = [privateKey addToKeychain:_keychain error:&error];
        should(!result);
        should([error code] == errSecDuplicateItem);
    }
    
    // Try listing public keys.
    @autoreleasepool {
        NSArray *keys = [_keychain publicKeys];
        should([keys count] == 1);
        LKKCKey *key = [keys objectAtIndex:0];
        
        should(key.keyClass == LKKCKeyClassPublic);
        should(key.keyType == LKKCKeyTypeRSA);
        should(key.keySize == 2048);
        shouldBeEqual(key.label, @"test RSA key label");
        shouldBeEqual(key.tag, @"test RSA key tag");
    }
    
    // Try listing private keys.
    @autoreleasepool {
        NSArray *keys = [_keychain privateKeys];
        should([keys count] == 1);
        LKKCKey *key = [keys objectAtIndex:0];
        
        should(key.keyClass == LKKCKeyClassPrivate);
        should(key.keyType == LKKCKeyTypeRSA);
        should(key.keySize == 2048);
        shouldBeEqual(key.label, @"test RSA key label");
        shouldBeEqual(key.tag, @"test RSA key tag");
    }

    // Try retrieving the keys by persistent ID.
    @autoreleasepool {
        NSError *error = nil;
        
        LKKCKey *publicKey = [_keychain keyWithPersistentID:publicID];
        LKKCKey *privateKey = [_keychain keyWithPersistentID:privateID];
        
        should(publicKey != nil);
        should(privateKey != nil);
        should(publicKey.keyClass == LKKCKeyClassPublic);
        should(privateKey.keyClass == LKKCKeyClassPrivate);
        should(publicKey.keyType == LKKCKeyTypeRSA);
        should(privateKey.keyType == LKKCKeyTypeRSA);
        should(publicKey.keySize == 2048);
        should(privateKey.keySize == 2048);
        shouldBeEqual(publicKey.label, @"test RSA key label");
        shouldBeEqual(privateKey.label, @"test RSA key label");
        shouldBeEqual(publicKey.tag, @"test RSA key tag");
        shouldBeEqual(privateKey.tag, @"test RSA key tag");
        
        result = [publicKey deleteItemWithError:&error];
        should(result);
        result = [privateKey deleteItemWithError:&error];
        should(result);
        
        LKKCKey *publicKey2 = [_keychain keyWithPersistentID:publicID];
        should(publicKey2 == nil);
        LKKCKey *privateKey2 = [_keychain keyWithPersistentID:privateID];
        should(privateKey2 == nil);
        
        [publicID release];
        publicID = nil;
        
        [privateID release];
        privateID = nil;
    }
    
    // Try generating a floating keypair.
    @autoreleasepool {
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:nil];
        should(generator != nil);
        generator.label = @"floating RSA key label";
        generator.tag = @"floating RSA key tag";
        LKKCKeyPair *keypair = [generator generateRSAKeyPair];
        should(keypair == nil);
    }
}

- (void)testRSAEncryption
{
    NSError *error = nil;
    
    LKKCKeyGenerator *generator = [LKKCKeyGenerator generatorWithKeychain:_keychain];
    generator.extractable = NO;
    generator.label = @"RSA test key";
    generator.tag = @"RSA test key tag";
    LKKCKeyPair *keypair = [generator generateRSAKeyPair];
    should(keypair != nil);
    
    NSString *message = @"This is some sample plaintext";
    NSData *plaintext = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertext = [keypair encryptData:plaintext error:&error];
    should(ciphertext != nil);
    
    NSData *decryptedtext = [keypair decryptData:ciphertext error:&error];
    should(decryptedtext != nil);
    shouldBeEqual(decryptedtext, plaintext);
    NSString *decryptedMessage = [[[NSString alloc] initWithData:decryptedtext encoding:NSUTF8StringEncoding] autorelease];
    shouldBeEqual(decryptedMessage, message);
}

@end
