
using System.Timers;

namespace SharpScape.Website.Services
{

    public class RefreshTimer
    {
        private static System.Timers.Timer aTimer;

        /// <summary>
        /// Sets up timer event for when the access token is about to expire. 
        /// </summary>
        private static void SetTimer()
        {
            // Create a timer with a 4 mins and 30 secs interval.
            aTimer = new System.Timers.Timer(270000);
            // Hook up the Elapsed event for the timer. 
            aTimer.Elapsed += RefreshTokenEvent;
            aTimer.AutoReset = true;
            aTimer.Enabled = true;
        }

        /// <summary>
        /// Calls the Api to refresh the Access Token.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="e"></param>
        private static void RefreshTokenEvent(Object source, ElapsedEventArgs e)
        {
            
            //var result = await Http.PostAsJsonAsync("api/refresh", userLoginDto);

            //set the the old access token to the new one. 
        }
    }
}
