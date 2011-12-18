//
//  LKKCKeychain.h
//  LKKCKeychain
//
//  Created by Karoly Lorentey on 2011-10-22.
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

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@class LKKCGenericPassword;
@class LKKCInternetPassword;
@class LKKCCertificate;
@class LKKCIdentity;
@class LKKCKey;

/** Represents a keychain.
 */
@interface LKKCKeychain : NSObject
{
@private
    SecKeychainRef _skeychain;
}

/** --------------------------------------------------------------------------------
 @name Opening keychains 
 -------------------------------------------------------------------------------- */

/** Returns the default keychain. */
+ (LKKCKeychain *)defaultKeychain;

/** Opens a keychain at a given filesystem path. 
 @param path The path to open.
 @param error On output, the error that occurred in case the keychain could not be opened (optional).
 @return An LKKCKeychain object representing the keychain at path, or nil in case of an error.
 */
+ (LKKCKeychain *)keychainWithPath:(NSString *)path error:(NSError **)error;

/** Initializes an LKKCKeychain object wrapping the specified keychain reference.
 @param skeychain The SecKeychainRef value.
 @return An LKKCKeychain object representing the given keychain reference.
 */
+ (LKKCKeychain *)keychainWithSecKeychain:(SecKeychainRef)skeychain;

/** Creates a new keychain.
 
 The new keychain is automatically unlocked.
 
 @param path The filesystem path of the new keychain.
 @param password The password for the new keychain. If nil, the system prompts the user for a password.
 @param error On output, the error on occured in case the keychain could not be created (optional).
 @return An LKKCKeychain object representing the new keychain.
 */
+ (LKKCKeychain *)createKeychainWithPath:(NSString *)path password:(NSString *)password error:(NSError **)error; 

/** Returns all keychains on the keychain search list.
 @return All keychains on the keychain search list.
 */
+ (NSArray *)keychainsOnSearchList;

/** --------------------------------------------------------------------------------
 @name Controlling user interaction
 -------------------------------------------------------------------------------- */

/** Returns whether the system is allowed to prompt the user.
 
 Prompts are used to unlock a keychain, to confirm a protected operation, etc. 
 When user interactions are disabled, operations that would require a prompt return an error. 
 @see setUserInteractionAllowed: 
 */
+ (BOOL)userInteractionAllowed;

/** Controls whether the system is allowed to prompt the user.
 
 Prompts are used to unlock a keychain, to confirm a protected operation, etc. 
 When user interactions are disabled, operations that would require a prompt return an error. 
 @param allowed If YES, prompts are allowed, otherwise they are supressed.
 @see userInteractionAllowed
 */
+ (void)setUserInteractionAllowed:(BOOL)allowed;

/** --------------------------------------------------------------------------------
 @name Generic passwords
 -------------------------------------------------------------------------------- */

/** Returns an array of all generic passwords on this keychain. 
 @return An array of all generic passwords on this keychain. 
 */
- (NSArray *)genericPasswords;

/** Returns the generic password with the given persistent ID.
 @param persistentID A persistent ID previously returned by -[LKKCGenericPassword persistentID].
 @return The generic password with _persistentID_, or nil if not found.
 */
- (LKKCGenericPassword *)genericPasswordWithPersistentID:(NSData *)persistentID;

/** Returns the generic password with the given _service_ and _account_ values.
 
 Generic passwords are uniquely identified by these two attributes.
 
 @param service The value of the service attribute.
 @param account The value of the account attribute.
 @return The generic password with _service_ and _account_, or nil if there is no such password on this keychain. */
- (LKKCGenericPassword *)genericPasswordWithService:(NSString *)service account:(NSString *)account;

/** --------------------------------------------------------------------------------
 @name Internet passwords
 -------------------------------------------------------------------------------- */

/** Returns an array of all internet passwords on this keychain. 
 @return An array of all internet passwords on this keychain. 
 */
- (NSArray *)internetPasswords;

/** Returns the internet password with the given persistent ID.
 @param persistentID A persistent ID previously returned by -[LKKCInternetPassword persistentID].
 @return The internet password with _persistentID_, or nil if not found.
 */
- (LKKCInternetPassword *)internetPasswordWithPersistentID:(NSData *)persistentID;

- (NSArray *)internetPasswordsForServer:(NSString *)server;

/** --------------------------------------------------------------------------------
 @name Certificates
 -------------------------------------------------------------------------------- */

/** Returns an array of all certificates on this keychain. 
 @return An array of all certificates on this keychain. 
 */
- (NSArray *)certificates;

/** Returns the certificate with the given persistent ID.
 @param persistentID A persistent ID previously returned by -[LKKCCertificate persistentID].
 @return The certificate with _persistentID_, or nil if not found.
 */
- (LKKCCertificate *)certificateWithPersistentID:(NSData *)persistentID;

- (NSArray *)certificatesWithSubject:(NSData *)subject;
- (NSArray *)certificatesWithPublicKeyHash:(NSData *)publicKeyHash;
- (NSArray *)certificatesWithLabel:(NSString *)label;

/** --------------------------------------------------------------------------------
 @name Identities
 -------------------------------------------------------------------------------- */

/** Returns an array of all identities on this keychain. 
 @return An array of all identities on this keychain. 
 */
- (NSArray *)identities;

/** --------------------------------------------------------------------------------
 @name Keys
 -------------------------------------------------------------------------------- */

/** Returns an array of all public keys on this keychain. 
 @return An array of all public keys on this keychain. 
 */
- (NSArray *)publicKeys;

/** Returns an array of all private keys on this keychain. 
 @return An array of all private keys on this keychain. 
 */
- (NSArray *)privateKeys;

/** Returns an array of all symmetric keys on this keychain. 
 @return An array of all symmetric keys on this keychain. 
 */
- (NSArray *)symmetricKeys;

/** Returns the key with the given persistent ID.
 @param persistentID A persistent ID previously returned by -[LKKCKey persistentID].
 @return The key with _persistentID_, or nil if not found.
 */
- (LKKCKey *)keyWithPersistentID:(NSData *)persistentID;

- (NSArray *)publicKeysWithLabel:(NSString *)label;
- (NSArray *)privateKeysWithLabel:(NSString *)label;
- (NSArray *)symmetricKeysWithLabel:(NSString *)label;


/** --------------------------------------------------------------------------------
 @name Keychain status
 -------------------------------------------------------------------------------- */

/** Whether this keychain is currently locked.
 
 The contents of locked keychains are inaccessible.
 @see lockWithError:
 @see unlockWithPassword:error:
 */
@property (readonly, getter = isLocked) BOOL locked;

/** Whether this keychain is currently readable to this application. */
@property (readonly, getter = isReadable) BOOL readable;
/** Whether this keychain is currently writable by this application. */
@property (readonly, getter = isWritable) BOOL writable;

/** --------------------------------------------------------------------------------
 @name Keychain properties
 -------------------------------------------------------------------------------- */

/** The filesystem path to this keychain.
 
 This is a readonly property. 
 You can move a keychain by using the filesystem API to move the file that represents it.
 */
@property (readonly) NSString *path;


/** Whether this keychain is automatically locked when the system goes to sleep.
 
 The keychain must be unlocked to access this value. 
 If the keychain is locked, this property returns NO.
 @see setLockOnSleep:error:
 */
@property (nonatomic, readonly) BOOL lockOnSleep;

/** The time interval after which this keychain is automatically locked, or 0 if there is no such timeout.
 
 The keychain must be unlocked to access this value. 
 If the keychain is locked, this property returns -1.
 
 @see setLockInterval:error:
 */
@property (nonatomic, readonly) NSTimeInterval lockInterval;

/** Controls whether this keychain is automatically locked when the system goes to sleep.
 @param lockOnSleep If YES, the keychain will be automatically locked when the system goes to sleep.
 @param error On output, the error that occurred in case the property could not be set (optional).
 @return YES if the operation succeeded, or NO if an error happened.
 @see lockOnSleep 
 */
- (BOOL)setLockOnSleep:(BOOL)lockOnSleep error:(NSError **)error;

/** Sets the time interval after which this keychain is automatically locked.
 @param lockInterval The lock time interval. Zero value disables automatic locking.
 @param error On output, the error that occurred in case the property could not be set (optional).
 @return YES if the operation succeeded, or NO if an error happened.
 @see lockInterval
 */
- (BOOL)setLockInterval:(NSTimeInterval)lockInterval error:(NSError **)error;

/** --------------------------------------------------------------------------------
 @name Keychain operations
 -------------------------------------------------------------------------------- */

/** Lock this keychain.
 @param error On output, the error that occurred in case the keychain could not be locked (optional).
 @return YES if the operation succeeded, or NO if an error happened.
 @see unlockWithPassword:error:
 */
- (BOOL)lockWithError:(NSError **)error;

/** Unlock this keychain.
 @param password The password to use to unlock the keychain. If nil, the system will prompt the user for a password.
 @param error On output, the error that occurred in case the keychain could not be unlocked (optional).
 @return YES if the operation succeeded, or NO if an error happened.
 @see lockWithError:
 @see setUserInteractionAllowed: */
- (BOOL)unlockWithPassword:(NSString *)password error:(NSError **)error;

/** Delete this keychain.
 
 If this operation succeeds, the contents of this keychain are irretrievably lost, 
 and this object becomes invalidated. All subsequent operations will throw an exception.
 @param error On output, the error that occurred in case the keychain could not be deleted (optional).
 @return YES if the operation succeeded, or NO if an error happened.
 */
- (BOOL)deleteKeychainWithError:(NSError **)error;

/** Returns the underlying keychain reference.
 @return The SecKeychainRef value that belongs to this keychain object.
 */
- (SecKeychainRef)SecKeychain;
@end
