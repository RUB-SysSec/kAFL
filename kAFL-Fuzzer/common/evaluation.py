"""
Copyright (C) 2017 Sergej Schumilo

This file is part of kAFL Fuzzer (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.
"""

import time, os
from common.debug import log_eval

class Evaluation:

	def __init__(self, config):
		self.config = config
		if self.config.argument_values['e']:
			self.start_time = time.time()
			if os.path.exists(self.config.argument_values['work_dir'] + "/evaluation/data.csv"):
				last = ""
				with open(self.config.argument_values['work_dir'] + "/evaluation/data.csv", "rb") as f:
					first = f.readline()
					f.seek(-2, 2)
					while f.read(1) != b"\n":
						f.seek(-2, 1)
					last = f.readline()
				self.time_offset = float(last.split(";")[0])
				log_eval("[EVAL]\tTime offset for evaluation file is " + str(self.time_offset))
				self.performance_file = open(self.config.argument_values['work_dir'] + "/evaluation/data.csv", "a")
			else:
				self.time_offset = 0.0
				self.performance_file = open(self.config.argument_values['work_dir'] + "/evaluation/data.csv", "w")
			self.__write_plot_file()
			self.__write_converter_file()
			self.enabled = True
		else:
			self.enabled = False

	def __del__(self):
		self.performance_file.close()

	def __write_converter_file(self):
		script = "require 'csv'\n" +\
				"last_time = nil\n" +\
				"first_time = nil\n" +\
				"acc = nil\n" +\
				"count = 0\n" +\
				"CSV.open('converted.csv', 'wb') do |csv|\n" +\
				"  CSV.foreach('data.csv',col_sep: \";\") do |row|\n" +\
				"    time,*data = *row\n" +\
				"    time = time.to_i\n" +\
				"    data = data.map(&:to_i)\n" +\
				"    first_time = time unless first_time\n" +\
				"    acc ||= data.map{0}\n" +\
				"    acc.each_index{|i| acc[i]+=data[i]}\n" +\
				"    count += 1\n" +\
				"    if !last_time || time - last_time > 2\n" +\
				"      csv << [time-first_time, *(acc.map{|v| v/count.to_f})]\n" +\
				"      last_time = time\n" +\
				"      acc = acc.map{0}\n" +\
				"      count = 0\n" +\
				"    end\n" +\
				"  end\n" +\
				"end\n"

		f = open(self.config.argument_values['work_dir'] + "/evaluation/convert.rb", "w")
		f.write(script)
		f.close()

	def __write_plot_file(self):

		script =	"reset\n" +\
					"system(\"ruby convert.rb\")\n" +\
					"set terminal wxt size 1200,800\n" +\
					"set multiplot\n" +\
					"set grid xtics linetype 0 linecolor rgb '#d0d0d0'\n" +\
					"set grid ytics linetype 0 linecolor rgb '#d0d0d0'\n" +\
					"set border linecolor rgb '#50c0f0'\n" +\
					"set tics textcolor rgb '#000000'\n" +\
					"set key outside\n" +\
					"set size 1, 0.25\n" +\
					"set datafile separator ','\n" +\
					"set xdata time\n" +\
					"set format x \"Day %j\\n %H:%M\"\n" +\
					"set timefmt '%s'\n" +\
					"set style line 2\n" +\
					"set style data line\n" +\
					"set origin 0.0,0.75\n" +\
					"plot 'converted.csv' using 1:2 title 'Performance' with line linecolor rgb '#0090ff' linewidth 2 smooth bezier, \\\n" +\
					"'' using 1:2 with filledcurve x1 title '' linecolor rgb '#0090ff' fillstyle transparent solid 0.2 noborder,\n" +\
					"set origin 0.0,0.5\n" +\
					"plot 'converted.csv' \\\n" +\
					"   using 1:4 title 'Pending' with lines linecolor rgb '#404040' linewidth 3, \\\n" +\
					"'' using 1:14 title 'Pending Favs' with lines linecolor rgb '#808080' linewidth 3, \\\n" +\
					"'' using 1:3 title 'Findings' with lines linecolor rgb '#C0C0C0' linewidth 2, \\\n" +\
					"'' using 1:5 title 'Favorites' with lines linecolor rgb '#FF0000' linewidth 2, \\\n" +\
					"'' using 1:3 with filledcurve x1 title '' linecolor rgb '#C0C0C0' fillstyle transparent solid 0.3 noborder, \\\n" +\
					"'' using 1:4 with filledcurve x1 title '' linecolor rgb '#808080' fillstyle transparent solid 0.5 noborder, \\\n" +\
					"'' using 1:14 with filledcurve x1 title '' linecolor rgb '#404040' fillstyle transparent solid 0.5 noborder\n" +\
					"set origin 0.0,0.25\n" +\
					"plot 'converted.csv' \\\n" +\
					"   using 1:7 title 'Unique Panics' with lines, \\\n" +\
					"'' using 1:9 title 'KASan Unique' with lines, \\\n" +\
					"'' using 1:11 title 'Timeout Unique' with lines\n" +\
					"set origin 0.0,0.0\n" +\
					"plot 'converted.csv' using 0:15 title 'Blacklisted BB' with lines\n" +\
					"pause 2\n" +\
					"unset multiplot\n" +\
					"reread\n"

		f = open(self.config.argument_values['work_dir'] + "/evaluation/plot.gnu", "w")
		f.write(script)
		f.close()


	def write_data(self, state, blacklisted):
		# Format: Time; Performance; Paths, Pending; Favorites; Panics; Panics Unique; Kasan; Kasan Unique; Timeout; Timeout Unique; Level; Cycles
		if self.enabled:
			self.performance_file.write(\
				str(((time.time()-self.start_time)+self.time_offset)) + ";" + \
				str(state.get_performance()) + ";" + \
				str(state.hashes) + ";" + \
				str(state.path_pending) + ";" + \
				str(state.favorites) + ";" + \
				str(state.panics) + ";" + \
				str(state.panics_unique) + ";" + \
				str(state.kasan) + ";" + \
				str(state.kasan_unique) + ";" + \
				str(state.reloads) + ";" + \
				str(state.reloads_unique) + ";" +\
				str(state.level) + ";" +\
				str(state.cycles) + ";" +\
				str(state.fav_pending) + ";" +\
				str(blacklisted)+ "\n")
			self.performance_file.flush()
