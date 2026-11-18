# Detection logic

1. Imppossible travel
   - if q1.ip_lat && q1.ip_lon___func_check_travel_possibility(q2.iplat && q2.iplon)
     - normal
     - else return impossible_travel_flag
1. Scope/object-access deviation
   - consider a object storing normal scope with scope as key and its relevancy (0 to 1 ) to the users usage 
   - if scope_relevancy > threshhold
   - return Scope/object-access deviation_flag
1. Temporal anomaly
   - same relevenacy logic as above but for timing
1. Volume/velocity anomaly
   - if volume anamoly found , then chekc for above logics flag , if ambiguity is consistent, then terminate the session and revoke the prticular key 
   - else monitor the activity and found relevent volume anaomly , and even if not found, just inform the user on the out of bound trusted communication platform