import time
import sys

if __name__ == "__main__":
    print("this file should be not executed standalone")
    sys.exit(1)


class TimeSeriesDatabase:

    def __init__(self, depth=10):
        self.depth = depth  # depth of TS in seconds
        self.tsdb = []  # just list of tuples (ts,metric,value,[tag1,tag2])
        self.related_tags = {}  # dictionary tag -> tags where one can find all related tags
        self.related_metrics = {}  # dictionary tag -> metrics

    def append_list(self, data, timestamp):
        if data is None:
            return  # nothing to add

        for item in data:
            (t_time, t_metric, t_value, t_tags) = item
            t_time = timestamp
            self.append((t_time, t_metric, t_value, t_tags))

    def get_related_tags(self, tag):
        return self.related_tags[tag]

    def get_related_metrics(self, tag):
        return self.related_metrics[tag]

    def append(self, item):

        # just append (and item should be something. like (ts,metric,value,[tag1,tag2])
        self.tsdb.append(item)

        # ensure up-to-date tag map

        for tag in item[3]:
            if tag not in self.related_tags:
                self.related_tags[tag] = []
            for tag2 in item[3]:
                if tag2 not in self.related_tags[tag] and tag2 != tag:
                    self.related_tags[tag].append(tag2)
            if tag not in self.related_metrics:
                self.related_metrics[tag] = []
            if item[1] not in self.related_metrics[tag]:
                self.related_metrics[tag].append(item[1])

    def cleanup(self):

        # go over the db and remove items older than max depth. #TODO: consider calling from append, or append_list
        now = int(time.time())

        for item in self.tsdb:
            if (item[0] + self.depth) < now:  # item is older than.
                self.tsdb.remove(item)

    @staticmethod
    def all_tags_matched(tags_to_match, tag_set):
        for tag in tags_to_match:
            if tag not in tag_set:
                return False
            else:
                continue
        return True  # everything matched

    def rate(self, metric, tags):

        # find first:

        first = None
        last = None

        for item in self.tsdb:
            if metric not in item[1]:
                continue

            if not TimeSeriesDatabase.all_tags_matched(tags, item[3]):
                continue
            else:
                first = item
                break

        for i in range(1, (len(self.tsdb) + 1)):
            item = self.tsdb[len(self.tsdb) - i]
            if metric not in item[1]:
                continue

            if not TimeSeriesDatabase.all_tags_matched(tags, item[3]):
                continue
            else:
                last = item
                break

        # now we have smth like:
        # first =  (1533907231, 'LocalLinkIntegrityErrors', 11, ['co5504','local'])
        # last = (1533907231, 'LocalLinkIntegrityErrors', 11, ['co5504','local'])

        # here we'll convert it to rate

        diff_time = None

        try:
            diff_time = int(last[0]) - int(first[0])  # time diff (in seconds as we use unix timestamps)
            diff_value = int(last[2]) - int(first[2])  # counter value diff.
            rate = int((float(diff_value) / float(diff_time)) * float(3600))

        except ZeroDivisionError:
            return 0, diff_time  # we divided by zero, because zero time... :)
        except TypeError:
            return None, None  # we have no data

        # TODO: check if the value grow is monotonic / check for possible overflows.. But not sure what to do with them...
        # TODO: maybe also reduce the amount of returned items..

        return rate, first[2], last[2], diff_time
