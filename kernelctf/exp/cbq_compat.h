/* CBQ definitions removed from newer kernel headers */
#ifndef _CBQ_COMPAT_H
#define _CBQ_COMPAT_H

#ifndef TCA_CBQ_RATE
enum {
	TCA_CBQ_UNSPEC,
	TCA_CBQ_LSSOPT,
	TCA_CBQ_WRROPT,
	TCA_CBQ_FOPT,
	TCA_CBQ_OVL_STRATEGY,
	TCA_CBQ_RATE,
	TCA_CBQ_RTAB,
	TCA_CBQ_POLICE,
	__TCA_CBQ_MAX,
};
struct tc_cbq_lssopt {
	unsigned char	change;
	unsigned char	flags;
	unsigned char	ewma_log;
	unsigned char	level;
	__u32		maxidle;
	__u32		minidle;
	__u32		offtime;
	__u32		avpkt;
};
struct tc_cbq_wrropt {
	unsigned char	flags;
	unsigned char	priority;
	unsigned char	cpriority;
	unsigned char	__reserved;
	__u32		allot;
	__u32		weight;
};
#define TCF_CBQ_LSS_BOUNDED	1
#define TCF_CBQ_LSS_ISOLATED	2
#define TCF_CBQ_LSS_FLAGS	0
#define TCF_CBQ_LSS_EWMA	1
#define TCF_CBQ_LSS_MAXIDLE	2
#define TCF_CBQ_LSS_MINIDLE	3
#define TCF_CBQ_LSS_OFFTIME	4
#define TCF_CBQ_LSS_AVPKT	5
#endif

#endif
