#import "AppDelegate+FirebasePlugin.h"
#import "FirebasePlugin.h"
#import "Firebase.h"
#import <objc/runtime.h>

@import FirebaseFirestore;

// Implement UNUserNotificationCenterDelegate to receive display notification via APNS for devices running iOS 10 and above.
// Implement FIRMessagingDelegate to receive data message via FCM for devices running iOS 10 and above.
@interface AppDelegate () <UNUserNotificationCenterDelegate, FIRMessagingDelegate>
@end

#define kApplicationInBackgroundKey @"applicationInBackground"
#define kDelegateKey @"delegate"

@implementation AppDelegate (FirebasePlugin)

static AppDelegate* instance;

+ (AppDelegate*) instance {
    return instance;
}

static NSDictionary* mutableUserInfo;
static FIRAuthStateDidChangeListenerHandle authStateChangeListener;
static bool authStateChangeListenerInitialized = false;
// static bool shouldEstablishDirectChannel = false;

- (void)setDelegate:(id)delegate {
    objc_setAssociatedObject(self, kDelegateKey, delegate, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (id)delegate {
    return objc_getAssociatedObject(self, kDelegateKey);
}

+ (void)load {
    Method original = class_getInstanceMethod(self, @selector(application:didFinishLaunchingWithOptions:));
    Method swizzled = class_getInstanceMethod(self, @selector(application:swizzledDidFinishLaunchingWithOptions:));
    method_exchangeImplementations(original, swizzled);
}

- (void)setApplicationInBackground:(NSNumber *)applicationInBackground {
    objc_setAssociatedObject(self, kApplicationInBackgroundKey, applicationInBackground, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (NSNumber *)applicationInBackground {
    return objc_getAssociatedObject(self, kApplicationInBackgroundKey);
}

- (BOOL)application:(UIApplication *)application swizzledDidFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [self application:application swizzledDidFinishLaunchingWithOptions:launchOptions];

    @try{
        instance = self;

        bool isFirebaseInitializedWithPlist = false;
        if(![FIRApp defaultApp]) {
            // get GoogleService-Info.plist file path
            NSString *filePath = [[NSBundle mainBundle] pathForResource:@"GoogleService-Info" ofType:@"plist"];

            // if file is successfully found, use it
            if(filePath){
                [FirebasePlugin.firebasePlugin _logMessage:@"GoogleService-Info.plist found, setup: [FIRApp configureWithOptions]"];
                // create firebase configure options passing .plist as content
                FIROptions *options = [[FIROptions alloc] initWithContentsOfFile:filePath];

                // configure FIRApp with options
                [FIRApp configureWithOptions:options];

                isFirebaseInitializedWithPlist = true;
            }else{
                // no .plist found, try default App
                [FirebasePlugin.firebasePlugin _logError:@"GoogleService-Info.plist NOT FOUND, setup: [FIRApp defaultApp]"];
                [FIRApp configure];
            }
        }else{
            // Firebase SDK has already been initialised:
            // Assume that another call (probably from another plugin) did so with the plist
            isFirebaseInitializedWithPlist = true;
        }



        // shouldEstablishDirectChannel = [[[NSBundle mainBundle] objectForInfoDictionaryKey:@"shouldEstablishDirectChannel"] boolValue];

        // Setup Firestore
        [FirebasePlugin setFirestore:[FIRFirestore firestore]];

        // Setup Google SignIn
        [GIDSignIn sharedInstance].clientID = [FIRApp defaultApp].options.clientID;
        [GIDSignIn sharedInstance].delegate = self;

        authStateChangeListener = [[FIRAuth auth] addAuthStateDidChangeListener:^(FIRAuth * _Nonnull auth, FIRUser * _Nullable user) {
            @try {
                if(!authStateChangeListenerInitialized){
                    authStateChangeListenerInitialized = true;
                }else{
                    [FirebasePlugin.firebasePlugin executeGlobalJavascript:[NSString stringWithFormat:@"FirebasePlugin._onAuthStateChange(%@)", (user != nil ? @"true": @"false")]];
                }
            }@catch (NSException *exception) {
                [FirebasePlugin.firebasePlugin handlePluginExceptionWithoutContext:exception];
            }
        }];

        self.applicationInBackground = @(YES);

    }@catch (NSException *exception) {
        [FirebasePlugin.firebasePlugin handlePluginExceptionWithoutContext:exception];
    }

    return YES;
}

# pragma mark - Google SignIn
- (void)signIn:(GIDSignIn *)signIn
didSignInForUser:(GIDGoogleUser *)user
     withError:(NSError *)error {
    @try{
        CDVPluginResult* pluginResult;
        if (error == nil) {
            GIDAuthentication *authentication = user.authentication;
            FIRAuthCredential *credential =
            [FIRGoogleAuthProvider credentialWithIDToken:authentication.idToken
                                           accessToken:authentication.accessToken];

            int key = [[FirebasePlugin firebasePlugin] saveAuthCredential:credential];
            NSMutableDictionary* result = [[NSMutableDictionary alloc] init];
            [result setValue:@"true" forKey:@"instantVerification"];
            [result setValue:[NSNumber numberWithInt:key] forKey:@"id"];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        } else {
          pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:error.description];
        }
        if ([FirebasePlugin firebasePlugin].googleSignInCallbackId != nil) {
            [[FirebasePlugin firebasePlugin].commandDelegate sendPluginResult:pluginResult callbackId:[FirebasePlugin firebasePlugin].googleSignInCallbackId];
        }
    }@catch (NSException *exception) {
        [FirebasePlugin.firebasePlugin handlePluginExceptionWithoutContext:exception];
    }
}

- (void)signIn:(GIDSignIn *)signIn
didDisconnectWithUser:(GIDGoogleUser *)user
     withError:(NSError *)error {
    NSString* msg = @"Google SignIn delegate: didDisconnectWithUser";
    if(error != nil){
        [FirebasePlugin.firebasePlugin _logError:[NSString stringWithFormat:@"%@: %@", msg, error]];
    }else{
        [FirebasePlugin.firebasePlugin _logMessage:msg];
    }
}

// Apple Sign In
- (void)authorizationController:(ASAuthorizationController *)controller
   didCompleteWithAuthorization:(ASAuthorization *)authorization API_AVAILABLE(ios(13.0)) {
    @try{
        CDVPluginResult* pluginResult;
        NSString* errorMessage = nil;
        FIROAuthCredential *credential;

        if ([authorization.credential isKindOfClass:[ASAuthorizationAppleIDCredential class]]) {
            ASAuthorizationAppleIDCredential *appleIDCredential = authorization.credential;
            NSString *rawNonce = [FirebasePlugin appleSignInNonce];
            if(rawNonce == nil){
                errorMessage = @"Invalid state: A login callback was received, but no login request was sent.";
            }else if (appleIDCredential.identityToken == nil) {
                errorMessage = @"Unable to fetch identity token.";
            }else{
                NSString *idToken = [[NSString alloc] initWithData:appleIDCredential.identityToken
                                                          encoding:NSUTF8StringEncoding];
                if (idToken == nil) {
                    errorMessage = [NSString stringWithFormat:@"Unable to serialize id token from data: %@", appleIDCredential.identityToken];
                }else{
                    // Initialize a Firebase credential.
                    credential = [FIROAuthProvider credentialWithProviderID:@"apple.com"
                        IDToken:idToken
                        rawNonce:rawNonce];

                    int key = [[FirebasePlugin firebasePlugin] saveAuthCredential:credential];
                    NSMutableDictionary* result = [[NSMutableDictionary alloc] init];
                    [result setValue:@"true" forKey:@"instantVerification"];
                    [result setValue:[NSNumber numberWithInt:key] forKey:@"id"];
                    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
                }
            }
            if(errorMessage != nil){
                [FirebasePlugin.firebasePlugin _logError:errorMessage];
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];
            }
            if ([FirebasePlugin firebasePlugin].appleSignInCallbackId != nil) {
                [[FirebasePlugin firebasePlugin].commandDelegate sendPluginResult:pluginResult callbackId:[FirebasePlugin firebasePlugin].appleSignInCallbackId];
            }
        }
    }@catch (NSException *exception) {
        [FirebasePlugin.firebasePlugin handlePluginExceptionWithoutContext:exception];
    }
}

- (void)authorizationController:(ASAuthorizationController *)controller
           didCompleteWithError:(NSError *)error API_AVAILABLE(ios(13.0)) {
    NSString* errorMessage = [NSString stringWithFormat:@"Sign in with Apple errored: %@", error];
    [FirebasePlugin.firebasePlugin _logError:errorMessage];
    if ([FirebasePlugin firebasePlugin].appleSignInCallbackId != nil) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];
        [[FirebasePlugin firebasePlugin].commandDelegate sendPluginResult:pluginResult callbackId:[FirebasePlugin firebasePlugin].appleSignInCallbackId];
    }
}

- (nonnull ASPresentationAnchor)presentationAnchorForAuthorizationController:(nonnull ASAuthorizationController *)controller  API_AVAILABLE(ios(13.0)){
    return self.viewController.view.window;
}

@end
