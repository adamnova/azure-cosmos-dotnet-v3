// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// ------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Encryption
{
    using System;
    using System.Diagnostics;

    // Lightweight value-type stopwatch to avoid allocating System.Diagnostics.Stopwatch.
    internal struct ValueStopwatch
    {
        private readonly long startTimestamp;

        private ValueStopwatch(long startTimestamp)
        {
            this.startTimestamp = startTimestamp;
        }

        public bool IsStarted => this.startTimestamp != 0;

        public static ValueStopwatch StartNew() => new (Stopwatch.GetTimestamp());

        public TimeSpan GetElapsedTime()
        {
            if (!this.IsStarted)
            {
                return TimeSpan.Zero;
            }

            long end = Stopwatch.GetTimestamp();
            long delta = end - this.startTimestamp;
            double seconds = (double)delta / Stopwatch.Frequency;
            return TimeSpan.FromSeconds(seconds);
        }
    }
}
