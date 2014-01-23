//
//  NCIChartView.m
//  NCIChart
//
//  Created by Ira on 12/22/13.
//  Copyright (c) 2013 FlowForwarding.Org. All rights reserved.
//

#import "NCIChartView.h"
#import "NCITopChartView.h"
#import "NCITopGridView.h"
#import "NCIBtmChartView.h"

@interface NCIChartView(){
    float btmChartHeigth;
    float chartsSpace;
    NSDictionary *topOptions;
    NSDictionary *bottomOptions;
}

@end

@implementation NCIChartView

- (id)initWithFrame:(CGRect)frame
{
    self = [super initWithFrame:frame];
    if (self) {
        
    }
    return self;
}

-(id)initWithFrame:(CGRect)frame andOptions:(NSDictionary *)opts{
    self = [self initWithFrame:frame];
    if (self) {
        if ([opts objectForKey:nciTopGraphOptions]){
            topOptions = [opts objectForKey:nciTopGraphOptions];
        }
        if ([opts objectForKey:nciBottomGraphOptions]){
            bottomOptions = [opts objectForKey:nciBottomGraphOptions];
        }
        if ([opts objectForKey:nciBottomChartHeight]){
            btmChartHeigth = [[opts objectForKey:nciBottomChartHeight] floatValue];
        }
        [self addGraps];
    }
    return self;
}

- (void)defaultSetup{
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad){
        btmChartHeigth =  90;
        chartsSpace = 30;
    } else {
        btmChartHeigth =  50;
        chartsSpace = 10;
    }
    _minRangeVal = NAN;
    _maxRangeVal = NAN;
    self.chartData = [[NSMutableArray alloc] init];
}

- (void)addGraps{
    _topChart = [[NCITopChartView alloc] initWithFrame:CGRectZero andOptions:topOptions];
    _topChart.chartData = self.chartData;
    _topChart.nciChart = self;
    _topChart.nciHasSelection = YES;
    _btmChart = [[NCIBtmChartView alloc] initWithFrame:CGRectZero andOptions:bottomOptions];
    _btmChart.chartData = self.chartData;
    _btmChart.nciHasSelection = NO;
    _btmChart.hasYLabels = NO;
    _btmChart.nciChart = self;
    [self addSubview:_topChart];
    [self addSubview:_btmChart];
}

- (void)addSubviews{

}

-(void)drawChart{
    [_topChart drawChart];
    [_btmChart drawChart];

}

- (void)resetChart{
    [self.chartData removeAllObjects];
}

- (void)layoutSubviews{
    _topChart.frame = CGRectMake(0, 0, self.frame.size.width, self.frame.size.height - btmChartHeigth - chartsSpace);
    _btmChart.frame = CGRectMake(0, self.frame.size.height - btmChartHeigth, self.frame.size.width, btmChartHeigth);
}

- (double)getScaleIndex{
    if (_minRangeVal != _minRangeVal || _maxRangeVal != _maxRangeVal)
        return 1;
    double rangeDiff = [self getRangesPeriod];
    if (rangeDiff == 0){
        return  1;
    } else {
        return [self getTimePeriod]/rangeDiff;
    }
}

-(double)getTimePeriod{
    if (self.chartData.count == 0)
        return 0;
    return [[self.chartData lastObject][0] doubleValue] - [self.chartData[0][0] doubleValue];
}

-(double)getRangesPeriod{
    return self.maxRangeVal - self.minRangeVal;
}

@end
