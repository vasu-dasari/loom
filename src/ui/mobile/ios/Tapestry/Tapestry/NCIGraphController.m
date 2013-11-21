//
//  NCIGraphController.m
//  Tapestry
//
//  Created by Ira on 11/11/13.
//  Copyright (c) 2013 Truststix. All rights reserved.
//

#import "NCIGraphController.h"
#import "NCIIndexValueView.h"
#import "NCIChartView.h"
#import "NCIHelpView.h"
#import "NCIEditServerView.h"
#import "NCIPeriodSwitcherPanel.h"
#import "NCIWebSocketConnector.h"

@interface NCIGraphController(){
    NCIIndexValueView *nciValue;
    NCIIndexValueView *nepValue;
    NCIIndexValueView *qpsValue;
    NCIChartView *graphView;
    UIButton *infoButton;
    NCIHelpView *helpView;

    UILabel *noConnectionLabel;
    NCIEditServerView *editServerView;
    NCIPeriodSwitcherPanel *switcherPanel;
    
    bool isShowingLandscapeView;
}
@end


@implementation NCIGraphController

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    self.title = NSLocalizedString(@"Tapestry: A Network Complexity Analyzer", nil);
    UIBarButtonItem* editButton = [[UIBarButtonItem alloc]  initWithImage:[UIImage imageNamed:@"actionsarrow"]
                                                                    style:UIBarButtonItemStyleBordered target:self action:@selector(showHelp)];
    [[self navigationItem] setRightBarButtonItem: editButton ];
    [self.navigationItem.rightBarButtonItem setTintColor:[UIColor whiteColor]];
    //for iOS 7 to make same calculations views y position
    if ([self respondsToSelector:@selector(edgesForExtendedLayout)]){
        self.edgesForExtendedLayout = UIRectEdgeNone;
        [self.navigationController.navigationBar setBarTintColor:[UIColor blackColor]];
        [self.navigationController.navigationBar setTitleTextAttributes:
         [NSDictionary dictionaryWithObjectsAndKeys:[UIColor whiteColor],
          UITextAttributeTextColor, nil]];
    } else {
        [self.navigationController.navigationBar setTintColor:[UIColor blackColor]];
    }
    
    nciValue = [[NCIIndexValueView alloc] initWithFrame:CGRectZero indName:NSLocalizedString(@"NCI", nil) indSize:22];
    [nciValue setTooltipText: NSLocalizedString(@"Network Complexity Index", nil)];
    
    [self.view addSubview:nciValue];
    qpsValue = [[NCIIndexValueView alloc] initWithFrame:CGRectZero
                                                indName:NSLocalizedString(@"Queries per Second", nil) indSize:14];
    
    [qpsValue setTooltipText:NSLocalizedString(@"Successful DNS Query Responses per Second", nil)];
    [self.view addSubview:qpsValue];
    
    nepValue = [[NCIIndexValueView alloc] initWithFrame:CGRectZero indName:NSLocalizedString(@"Endpoints", nil) indSize:14];
    [nepValue setTooltipText:NSLocalizedString(@"Number of Connected Network Elements", nil)];
    
    [self.view addSubview:nepValue];
    
    switcherPanel = [[NCIPeriodSwitcherPanel alloc] initWithFrame:CGRectZero];
    [self.view addSubview:switcherPanel];
    
    graphView = [[NCIChartView alloc] initWithFrame:CGRectZero];
    [self.view addSubview:graphView];
    
    editServerView = [[NCIEditServerView alloc] initWithFrame:CGRectZero];
    [self.view addSubview:editServerView];
    
    noConnectionLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    noConnectionLabel.text = NSLocalizedString(@"Can't connect, please try agian.", nil);
    noConnectionLabel.backgroundColor = [UIColor clearColor];
    noConnectionLabel.font = [UIFont boldSystemFontOfSize:22];
    noConnectionLabel.textAlignment = NSTextAlignmentCenter;
    noConnectionLabel.textColor = [UIColor redColor];
    [noConnectionLabel setHidden:YES];
    [self.view addSubview:noConnectionLabel];
    
    helpView = [[NCIHelpView alloc] initWithFrame:self.view.bounds];
    [self.view addSubview:helpView];
    
    [self layoutSubviews];
    
    //TODO reorganize this
    [NCIWebSocketConnector interlocutor].editServerView = editServerView;
    [NCIWebSocketConnector interlocutor].nciValue = nciValue;
    [NCIWebSocketConnector interlocutor].nepValue = nepValue;
    [NCIWebSocketConnector interlocutor].qpsValue = qpsValue;
    [NCIWebSocketConnector interlocutor].graphView = graphView;
    [NCIWebSocketConnector interlocutor].noConnectionLabel = noConnectionLabel;
    [[NCIWebSocketConnector interlocutor] reconnect];
    
    isShowingLandscapeView = NO;
    [[UIDevice currentDevice] beginGeneratingDeviceOrientationNotifications];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(orientationChanged:)
                                                 name:UIDeviceOrientationDidChangeNotification
                                               object:nil];
    [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleLightContent];
    
}

- (void)showHelp{
    [helpView showHelp];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)layoutSubviews {
    int topIndent = 10;
    int indexLabelHeight = 50;
    if (isShowingLandscapeView) {
        
    } else {
        
    }
    
    editServerView.frame = CGRectMake(0, topIndent, self.view.bounds.size.width, 170);
    
    nciValue.frame = CGRectMake(0, 2*topIndent + indexLabelHeight, self.view.bounds.size.width/2, indexLabelHeight);
    
    qpsValue.frame = CGRectMake(self.view.bounds.size.width/2, 2*topIndent + 2*indexLabelHeight + 25, self.view.bounds.size.width/2, indexLabelHeight);
    
    nepValue.frame = CGRectMake(self.view.bounds.size.width/2, indexLabelHeight + 2*topIndent, self.view.bounds.size.width/2, indexLabelHeight);
    
    switcherPanel.frame  = CGRectMake(20, 200, 500, 40);
    
    noConnectionLabel.frame = CGRectMake(0, 250, self.view.bounds.size.width, 50);
    
    graphView.frame = CGRectMake(0, 250, self.view.bounds.size.width, 450);
    
    infoButton.center = CGPointMake(self.view.bounds.size.width - 50, indexLabelHeight + 30);
    
    helpView.frame = self.view.bounds;
}

- (void)orientationChanged:(NSNotification *)notification
{
    UIDeviceOrientation deviceOrientation = [UIDevice currentDevice].orientation;
    if (UIDeviceOrientationIsLandscape(deviceOrientation) &&
        !isShowingLandscapeView)
    {
        [self layoutSubviews];
        isShowingLandscapeView = YES;
    }
    else if (UIDeviceOrientationIsPortrait(deviceOrientation) &&
             isShowingLandscapeView)
    {
        [self layoutSubviews];
        isShowingLandscapeView = NO;
    }
}

@end
