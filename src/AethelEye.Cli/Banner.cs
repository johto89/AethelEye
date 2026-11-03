namespace AethelEye.Cli;

/// <summary>ASCII identity shown on startup, help and the "banner" command.</summary>
internal static class Banner
{
    private const string Art = """
          ###   #####  #####  #   #  #####  #        #####  #   #  #####
         #   #  #        #    #   #  #      #        #       # #   #
         #####  ####     #    #####  ####   #        ####     #    ####
         #   #  #        #    #   #  #      #        #        # #   #
         #   #  #####    #    #   #  #####  #####    #####    #    #####
        """;

    public static void Show()
    {
        var previous = Console.ForegroundColor;
        try
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.Out.WriteLine(Art);

            Console.ForegroundColor = ConsoleColor.Red;
            Console.Out.WriteLine("                                  (o)");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Out.WriteLine("        Omniscient Reconnaissance Framework for the Modern Era");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Out.WriteLine("        v0.1.0  |  GPL-3.0  |  authorized testing only");
            Console.Out.WriteLine();
        }
        finally
        {
            Console.ForegroundColor = previous;
        }
    }
}
