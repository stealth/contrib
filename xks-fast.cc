// c++ -std=c++11 xks-fast.cc -Wall -O2
//
// avg speedup ~ 30%
//
// (C) 2014

#include <map>
#include <string>
#include <iostream>
#include <sys/time.h>
#include <stdint.h>

using namespace std;

uint64_t time_diff(const timeval &tv1, const timeval &tv2)
{
	uint64_t t1 = tv1.tv_sec*1000000 + tv1.tv_usec;
	uint64_t t2 = tv2.tv_sec*1000000 + tv2.tv_usec;
	return t2 - t1;
}


int main()
{
	map<string, map<string, string>> DB_fast;
	map<string, map<string, string>> DB_slow;
	char tmp[32];
	timeval tv1, tv2;

	// even count the init stuff!
	gettimeofday(&tv1, NULL);
	auto cit = DB_fast.begin();
	pair<string, map<string, string>> sm;
	sm.first = "tor_onion_survey";
	for (int i = 0; i < 100000; ++i) {
		snprintf(tmp, sizeof(tmp), "%d.bar.onion", i);
		sm.second["onion_address"] = tmp;
		sm.second["onion_scheme"] = tmp;
		sm.second["onion_port"] = tmp;
		sm.second["onion_count"] = tmp;
		DB_fast.insert(cit, sm);
		DB_fast.clear();
	}
	gettimeofday(&tv2, NULL);

	cout<<time_diff(tv1, tv2)<<"usec\n";

	gettimeofday(&tv1, NULL);
	for (int i = 0; i < 100000; ++i) {
		snprintf(tmp, sizeof(tmp), "%d.bar.onion", i);
		DB_slow["tor_onion_survey"]["onion_address"] = tmp;
		DB_slow["tor_onion_survey"]["onion_scheme"] = tmp;
		DB_slow["tor_onion_survey"]["onion_port"] = tmp;
		DB_slow["tor_onion_survey"]["onion_count"] = tmp;
		DB_slow.clear();
	}
	gettimeofday(&tv2, NULL);
	cout<<time_diff(tv1, tv2)<<"usec\n";


/* debug
	for (cit = DB_fast.begin(); cit != DB_fast.end(); ++cit) {
		for (auto cit2 = cit->second.begin(); cit2 != cit->second.end(); ++cit2)
			cout<<cit->first<<":"<<cit2->first<<":"<<cit2->second<<endl;
	}
	cout<<"----\n";
	for (cit = DB_slow.begin(); cit != DB_slow.end(); ++cit) {
		for (auto cit2 = cit->second.begin(); cit2 != cit->second.end(); ++cit2)
			cout<<cit->first<<":"<<cit2->first<<":"<<cit2->second<<endl;
	}

*/
	return 0;
}

