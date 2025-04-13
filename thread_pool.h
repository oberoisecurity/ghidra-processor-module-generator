//-----------------------------------------------------------------------------
// File: thread_pool.h
//
// Thread pool helpers
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//------------------------------------------------------------------------------
#pragma once

#include <boost/asio/thread_pool.hpp>
#include <boost/atomic.hpp>

void resetThreadPool(void);
void incrementWorkerFailures(void);
unsigned int getWorkerFailures(void);
void incrementWorkerCompletions(void);
unsigned int getWorkerCompletions(void);
