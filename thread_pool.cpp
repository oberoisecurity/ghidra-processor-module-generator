//-----------------------------------------------------------------------------
// File: parser.cpp
//
// Thread pool helpers
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//------------------------------------------------------------------------------
#include "thread_pool.h"
#include <boost/asio/thread_pool.hpp>
#include <boost/atomic.hpp>

// count of successful and failed worker jobs
// use atomic for thread-safety
static boost::atomic<unsigned int> g_CompletedCount = 0;
static boost::atomic<unsigned int> g_FailureCount = 0;

// reset thread pool counters
void resetThreadPool(void)
{
    g_FailureCount = 0;
    g_CompletedCount = 0;
}

// increment the number of worker completions
void incrementWorkerCompletions(void)
{
    g_CompletedCount++;
}

// get the number of completed workers
unsigned int getWorkerCompletions(void)
{
    return g_CompletedCount;
}

// increment the number of failures
void incrementWorkerFailures(void)
{
    g_FailureCount++;
}

// get the number of failures
unsigned int getWorkerFailures(void)
{
    return g_FailureCount;
}
