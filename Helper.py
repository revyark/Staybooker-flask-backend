from datetime import datetime,date,timedelta
def set_service_fee(Check_in,Check_out,base_fee,dynamic_pricings):
    date_list=[]
    service_fee=0
    n=Check_out-Check_in
    for i in range(n.days):
        date_list.append({'Date':Check_in + timedelta(days=i),'Price':0,'D/P':False})
    # for i in range(n.days+1):
    #     print(date_list[i])
    for i in range(n.days):
        for dynamic_pricing in dynamic_pricings:
            if (dynamic_pricing.Check_in<=date_list[i]['Date'] and date_list[i]['Date']<=dynamic_pricing.Check_out):
                date_list[i]['Price']=dynamic_pricing.Price
                date_list[i]['D/P']=True
                break
        if (not date_list[i]['D/P']):
            date_list[i]['Price']=base_fee
        print(date_list[i])
    for i in range(n.days):
        service_fee+=date_list[i]['Price']
    return service_fee

