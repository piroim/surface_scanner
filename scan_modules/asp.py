"""Classic ASP, ASP.NET, and .NET web framework fingerprints."""

from __future__ import annotations

from .base import Signature, TechnologyModule, regex


class AspModule(TechnologyModule):
    key = "asp"
    label = "ASP/.NET"
    aliases = ("asp", "aspx", "dotnet", ".net")
    route_suffixes = (".asp", ".aspx", ".asmx", ".ashx", ".axd")
    signatures = (
        Signature("header", regex(r".+"), "런타임", "ASP.NET", "high", "x-aspnet-version"),
        Signature("header", regex(r".+"), "프레임워크", "ASP.NET MVC", "high", "x-aspnetmvc-version"),
        Signature("header", regex(r"ASP\.NET"), "런타임", "ASP.NET", "high", "x-powered-by"),
        Signature("header", regex(r"ASP\.NET_SessionId"), "세션", "ASP.NET Session", "high", "set-cookie"),
        Signature("header", regex(r"ARRAffinity"), "인프라", "Azure App Service/ARR", "medium", "set-cookie"),
        Signature("body", regex(r"__VIEWSTATE|__EVENTVALIDATION|id=[\"']aspnetForm"), "프레임워크", "ASP.NET Web Forms", "high"),
        Signature("body", regex(r"Microsoft\.AspNetCore|ASP\.NET Core"), "프레임워크", "ASP.NET Core", "high"),
        Signature("body", regex(r"/_layouts/15/|MicrosoftSharePointTeamServices"), "제품", "Microsoft SharePoint", "high"),
    )


MODULE = AspModule()
