require 'csv'
require 'tempfile'

class MultipleIssuesForUniqueValue < Exception
end

class NoIssueForUniqueValue < Exception
end

class Journal < ActiveRecord::Base
  def empty?(*args)
    (details.empty? && notes.blank?)
  end
end

class ImporterController < ApplicationController
  unloadable

  before_filter :find_project

  ISSUE_ATTRS = [:id, :subject, :assigned_to, :fixed_version,
    :author, :description, :category, :priority, :tracker, :status,
    :start_date, :due_date, :done_ratio, :estimated_hours,
    #:parent_issue, :watchers ]
    :parent_issue, :watchers, :created_on ]

  def index
  end

  def match
    # Delete existing iip to ensure there can't be two iips for a user
    ImportInProgress.delete_all(["user_id = ?",User.current.id])
    # save import-in-progress data
    iip = ImportInProgress.find_or_create_by_user_id(User.current.id)
    iip.quote_char = params[:wrapper]
    iip.col_sep = params[:splitter]
    iip.encoding = params[:encoding]
    #iip.csv_data = params[:file].read
    iip.created = Time.new
    if params[:file]
      iip.csv_data = params[:file].read
    else
      flash[:warning] = l(:text_file_not_specified)
      redirect_to :action => 'index', :project_id => @project.id
      return
    end
    iip.save

    # Put the timestamp in the params to detect
    # users with two imports in progress
    @import_timestamp = iip.created.strftime("%Y-%m-%d %H:%M:%S")
    @original_filename = params[:file].original_filename

    # display sample
    sample_count = 5
    i = 0
    @samples = []

    begin
      CSV.new(iip.csv_data, {:headers=>true,
                             :converters => :all,
                             :encoding=>iip.encoding,
                             :quote_char=>iip.quote_char,
                             :col_sep=>iip.col_sep}).each do |row|
        @samples[i] = row

        i += 1
        if i >= sample_count
          break
        end
      end # do
    rescue => e
      msg = e.message + "\n" + e.backtrace.join("\n")
      logger.debug msg
      render :text => "CSV file read error: encoding error or " + e.message
      return
    end

    if @samples.size > 0
      @headers = @samples[0].headers

      (0..@headers.size-1).each do |num|
        unless @headers[num]
          @headers[num] = '------'
          flash[:warning] = "Column name empty error"
        end
        # header encoding
        @headers[num].to_s.force_encoding("utf-8")
      end
    end

    # fields
    @attrs = Array.new
    ISSUE_ATTRS.each do |attr|
      #@attrs.push([l_has_string?("field_#{attr}".to_sym) ? l("field_#{attr}".to_sym) : attr.to_s.humanize, attr])
      @attrs.push([l_or_humanize(attr, :prefix=>"field_"), attr])
    end
    @project.all_issue_custom_fields.each do |cfield|
      @attrs.push([cfield.name, cfield.name])
    end
    IssueRelation::TYPES.each_pair do |rtype, rinfo|
      @attrs.push([l_or_humanize(rinfo[:name]),rtype])
    end
    @attrs.sort!
  end

  # Returns the issue object associated with the given value of the given attribute.
  # Raises NoIssueForUniqueValue if not found or MultipleIssuesForUniqueValue
  def issue_for_unique_attr(unique_attr, attr_value, row_data)
    if @issue_by_unique_attr.has_key?(attr_value)
      return @issue_by_unique_attr[attr_value]
    end

    # 親チケットカラムが「トラッカー #ID: チケット名」の場合(Redmineの標準出力機能を用いた場合)の考慮追加
    if !(attr_value.blank?) && !(attr_value.to_s =~ /^\d+$/)
      attr_value = attr_value[/#\d+:/].blank? ? attr_value : attr_value[/#\d+:/][/\d+/]
    end

    if unique_attr == "id"
      issues = [Issue.find_by_id(attr_value)]
    else
      #query = Query.new(:name => "_importer", :project => @project)
      query = IssueQuery.new(:name => "_importer", :project => @project)
      query.add_filter("status_id", "*", [1])
      query.add_filter(unique_attr, "=", [attr_value])

      #issues = Issue.find :all, :conditions => query.statement, :limit => 2, :include => [ :assigned_to, :status, :tracker, :project, :priority, :category, :fixed_version ]
      begin
        issues = Issue.find :all, :conditions => query.statement, :limit => 2, :include => [ :assigned_to, :status, :tracker, :project, :priority, :category, :fixed_version ]
      rescue NoMethodError
        query = IssueQuery.new(:name => "_importer", :project => @project)
        query.add_filter("status_id", "*", [1])
        query.add_filter(unique_attr, "=", [attr_value.to_s])
        issues = Issue.find :all, :conditions => query.statement, :limit => 2, :include => [ :assigned_to, :status, :tracker, :project, :priority, :category, :fixed_version ]
      end
    end
    if issues.size > 1
      @failed_count += 1
      @failed_issues[@failed_count] = row_data
      #flash_message(:warning, "Unique field #{unique_attr} with value '#{attr_value}' in issue #{@failed_count} has duplicate record")
      flash_message(:warning, "Unique field #{unique_attr}#{unique_attr == @unique_attr ? '': '('+@unique_attr+')'} with value '#{attr_value}' has duplicate record")
      raise MultipleIssuesForUniqueValue, "Unique field #{unique_attr} with value '#{attr_value}' has duplicate record"
    else
      if issues.size == 0 || issues == [nil]
        raise NoIssueForUniqueValue, "No issue with #{unique_attr} of '#{attr_value}' found"
      end
      issues.first
    end
  end

  # Returns the id for the given user or raises RecordNotFound
  # Implements a cache of users based on login name
  def user_for_login!(login)
    begin
      if !@user_by_login.has_key?(login)
        @user_by_login[login] = User.find_by_login!(login)
      end
      @user_by_login[login]
    rescue ActiveRecord::RecordNotFound
      @unfound_class = "User"
      @unfound_key = login
      raise
    end
  end
  def user_id_for_login!(login)
    user = user_for_login!(login)
    user ? user.id : nil
  end


  # Returns the id for the given version or raises RecordNotFound.
  # Implements a cache of version ids based on version name
  # If add_versions is true and a valid name is given,
  # will create a new version and save it when it doesn't exist yet.
  def version_id_for_name!(project,name,add_versions)
    if !@version_id_by_name.has_key?(name)
      version = Version.find_by_project_id_and_name(project.id, name)
      if !version
        if name && (name.length > 0) && add_versions
          version = project.versions.build(:name=>name)
          version.save
        else
          @unfound_class = "Version"
          @unfound_key = name
          raise ActiveRecord::RecordNotFound, "No version named #{name}"
        end
      end
      @version_id_by_name[name] = version.id
    end
    @version_id_by_name[name]
  end

  def result
    @handle_count = 0
    @update_count = 0
    @skip_count = 0
    @failed_count = 0
    @failed_issues = Hash.new
    @affect_projects_issues = Hash.new
    # This is a cache of previously inserted issues indexed by the value
    # the user provided in the unique column
    @issue_by_unique_attr = Hash.new
    # Cache of user id by login
    @user_by_login = Hash.new
    # Cache of Version by name
    @version_id_by_name = Hash.new

    # Retrieve saved import data
    iip = ImportInProgress.find_by_user_id(User.current.id)
    if iip == nil
      flash[:error] = "No import is currently in progress"
      return
    end
    if iip.created.strftime("%Y-%m-%d %H:%M:%S") != params[:import_timestamp]
      flash[:error] = "You seem to have started another import " \
          "since starting this one. " \
          "This import cannot be completed"
      return
    end

    default_tracker = params[:default_tracker]
    update_issue = params[:update_issue]
    unique_field = params[:unique_field].empty? ? nil : params[:unique_field]
    update_journal_only = params[:update_journal_only]
    journal_field = params[:journal_field]
    journal_author = params[:journal_author]
    journal_created_on = params[:journal_created_on]
    update_other_project = params[:update_other_project]
    ignore_non_exist = params[:ignore_non_exist]
    fields_map = params[:fields_map]
    send_emails = params[:send_emails]
    add_categories = params[:add_categories]
    add_versions = params[:add_versions]
    add_custom_fields = params[:add_custom_fields]
    use_user_name = params[:use_user_name]
    @check_non_exist_user = params[:check_non_exist_user]
    unique_attr = fields_map[unique_field]
    @unique_attr = unique_attr
    unique_attr_checked = false  # Used to optimize some work that has to happen inside the loop

    # attrs_map is fields_map's invert
    attrs_map = fields_map.invert

    # check params
    unique_error = nil
    if update_issue
      unique_error = l(:text_rmi_specify_unique_field_for_update)
    elsif attrs_map["parent_issue"] != nil
      unique_error = l(:text_rmi_specify_unique_field_for_column,:column => l(:field_parent_issue))
    else
      IssueRelation::TYPES.each_key do |rtype|
        if attrs_map[rtype]
          unique_error = l(:text_rmi_specify_unique_field_for_column,:column => l("label_#{rtype}".to_sym))
          break
        end
      end
    end
    if unique_error && unique_field.nil?
      flash[:error] = unique_error
      return
    elsif unique_error && !unique_field.nil? && unique_attr.blank?
      flash[:error] = l(:text_rmi_specify_unique_field_for_unique, :column => unique_field)
      return
    end

    # trnaslate unique_attr if it's a custom field
    if unique_field && !ISSUE_ATTRS.include?(unique_attr.to_sym)
      @project.all_issue_custom_fields.each do |cf|
        if cf.name == unique_attr
          if !cf.is_filter
            flash[:error] = "Unique field #{unique_attr} is not filter"
            flash[:error] = l(:text_rmi_specify_unique_field_for_cf, :column => unique_attr)
            return
          end
          unique_attr = "cf_#{cf.id}"
          break
        end
      end
    end

    if use_user_name
      @users = {}
      User.find(:all).each do |u| @users[u.name] = u; end
    end

    CSV.new(iip.csv_data, {:headers=>true,
                           :converters => :all,
                           :encoding=>iip.encoding,
                           :quote_char=>iip.quote_char,
                           :col_sep=>iip.col_sep}).each do |row|

      ["author", "assigned_to", "parent_issue"].each do |a|
        row[attrs_map[a]] = nil if row[attrs_map[a]] == ''
      end

      project = Project.find_by_name(row[attrs_map["project"]])
      if !project
        project = @project
      end

      begin
        row.each{|k,v| row[k] = v.unpack('U*').pack('U*') if v.kind_of?(String)}

        tracker = Tracker.find_by_name(row[attrs_map["tracker"]])
        status = IssueStatus.find_by_name(row[attrs_map["status"]])
        #author = attrs_map["author"] ? user_for_login!(row[attrs_map["author"]]) : User.current
        author = find_user('author', row[attrs_map["author"]], User.current)
        priority = Enumeration.find_by_name(row[attrs_map["priority"]])
        category_name = row[attrs_map["category"]]
        category = IssueCategory.find_by_project_id_and_name(project.id, category_name)
        if (!category) && category_name && category_name.length > 0 && add_categories
          category = project.issue_categories.build(:name => category_name)
          category.save
        end
        #assigned_to = row[attrs_map["assigned_to"]] != nil ? user_for_login!(row[attrs_map["assigned_to"]]) : nil
        assigned_to = find_user('assigned_to', row[attrs_map["assigned_to"]]) if row[attrs_map["assigned_to"]]
        #fixed_version_name = row[attrs_map["fixed_version"]]
        fixed_version_name = row[attrs_map["fixed_version"]] if row[attrs_map["fixed_version"]].present? || nil
        fixed_version_id = fixed_version_name ? version_id_for_name!(project,fixed_version_name,add_versions) : nil
        watchers = row[attrs_map["watchers"]]
        # new issue or find exists one
        issue = Issue.new
        journal = nil
        issue.project_id = project != nil ? project.id : @project.id
        issue.tracker_id = tracker != nil ? tracker.id : default_tracker
        #issue.author_id = author != nil ? author.id : User.current.id
        issue.author_id = author.present? ? author.id : User.current.id
        issue.created_on = issue.updated_on = row[attrs_map["created_on"]]
      rescue ActiveRecord::RecordNotFound
        @failed_count += 1
        @failed_issues[@failed_count] = row
        flash_message(:warning, "When adding issue #{@failed_count} below, the #{@unfound_class} #{@unfound_key} was not found")
        next
      end

      # translate unique_attr if it's a custom field -- only on the first issue
      if !unique_attr_checked
        if unique_field && !ISSUE_ATTRS.include?(unique_attr.to_sym)
          issue.available_custom_fields.each do |cf|
            if cf.name == unique_attr
              unique_attr = "cf_#{cf.id}"
              break
            end
          end
        end
        unique_attr_checked = true
      end

      if update_issue
        begin
          issue = issue_for_unique_attr(unique_attr,row[unique_field],row)
          #issue.instance_eval { @current_journal = nil }

          # ignore other project's issue or not
          if issue.project_id != @project.id && !update_other_project
            @skip_count += 1
            next
          end

          # ignore closed issue except reopen
          #if issue.status.is_closed?
          #  if status == nil || status.is_closed?
          #    @skip_count += 1
          #    next
          #  end
          #end

          # init journal
          note = row[journal_field] || ''
          #journal = issue.init_journal(author || User.current,
          #  note || '')
          jauthor = find_user('journal author', row[journal_author], User.current)
          journal = issue.init_journal(jauthor, note || '')
          issue.updated_on = journal.created_on = row[journal_created_on]

          @update_count += 1

        rescue NoIssueForUniqueValue
          if ignore_non_exist
            @skip_count += 1
            next
          else
            @failed_count += 1
            @failed_issues[@failed_count] = row
            flash_message(:warning, "Could not update issue #{@failed_count} below, no match for the value #{row[unique_field]} were found")
            next
          end

        rescue MultipleIssuesForUniqueValue
          @failed_count += 1
          @failed_issues[@failed_count] = row
          flash_message(:warning, "Could not update issue #{@failed_count} below, multiple matches for the value #{row[unique_field]} were found")
          next
        end
      end

      # project affect
      if project == nil
        project = Project.find_by_id(issue.project_id)
      end
      @affect_projects_issues.has_key?(project.name) ?
        @affect_projects_issues[project.name] += 1 : @affect_projects_issues[project.name] = 1

      if issue.new_record? || (update_issue && !update_journal_only)
        # required attributes
        issue.status_id = status != nil ? status.id : issue.status_id
        issue.priority_id = priority != nil ? priority.id : issue.priority_id
        issue.subject = row[attrs_map["subject"]] || issue.subject

        # optional attributes
        issue.description = row[attrs_map["description"]] || issue.description
        issue.category_id = category != nil ? category.id : issue.category_id
        #issue.start_date = row[attrs_map["start_date"]] || issue.start_date
        #issue.due_date = row[attrs_map["due_date"]] || issue.due_date
        if row[attrs_map["start_date"]].present?
          issue.start_date = Date.parse(row[attrs_map["start_date"]]).strftime("%Y-%m-%d")
        else
          issue.start_date = issue.start_date
        end
        if row[attrs_map["due_date"]].present?
          issue.due_date = Date.parse(row[attrs_map["due_date"]]).strftime("%Y-%m-%d")
        else
          issue.due_date = issue.due_date
        end
        #issue.assigned_to_id = assigned_to != nil ? assigned_to.id : issue.assigned_to_id
        issue.assigned_to_id = assigned_to.present? ? assigned_to.id : issue.assigned_to_id
        issue.fixed_version_id = fixed_version_id != nil ? fixed_version_id : issue.fixed_version_id
        issue.done_ratio = row[attrs_map["done_ratio"]] || issue.done_ratio
        issue.estimated_hours = row[attrs_map["estimated_hours"]] || issue.estimated_hours

        # parent issues
        begin
          parent_value = row[attrs_map["parent_issue"]]
          if parent_value && (parent_value.length > 0)
            issue.parent_issue_id = issue_for_unique_attr(unique_attr,parent_value,row).id
          end
        rescue NoIssueForUniqueValue
          if ignore_non_exist
            @skip_count += 1
          else
            @failed_count += 1
            @failed_issues[@failed_count] = row
            flash_message(:warning, "When setting the parent for issue #{@failed_count} below, no matches for the value #{parent_value} were found")
            next
          end
        rescue MultipleIssuesForUniqueValue
          @failed_count += 1
          @failed_issues[@failed_count] = row
          flash_message(:warning, "When setting the parent for issue #{@failed_count} below, multiple matches for the value #{parent_value} were found")
          next
        end

        # custom fields
        custom_failed_count = 0
        issue.custom_field_values = issue.available_custom_fields.inject({}) do |h, cf|
          if value = row[attrs_map[cf.name]]
            begin
              if cf.field_format == 'user'
                #value = user_id_for_login!(value).to_s
                value = find_user('user', value).to_s
              elsif cf.field_format == 'version'
                value = version_id_for_name!(project,value,add_versions).to_s
              elsif cf.field_format == 'date'
                value = value.to_date.to_s(:db)
                org_value = value
                value = Date.parse(value).strftime("%Y-%m-%d") rescue value = org_value
              elsif add_custom_fields && cf.field_format == 'list' && !value.empty? && !cf.possible_values.include?(value)
                cf.possible_values << value
                cf.save!
              elsif cf.field_format == 'string' && !value.kind_of?(String)
                value = value.to_s
              end
              h[cf.id] = value
            rescue
              if custom_failed_count == 0
                custom_failed_count += 1
                @failed_count += 1
                @failed_issues[@failed_count] = row
              end
              flash_message(:warning, "When trying to set custom field #{cf.name} on issue #{@failed_count} below, value #{value} was invalid")
            end
          end
          h
        end
        next if custom_failed_count > 0

        # watchers
        watcher_failed_count = 0
        if watchers
          addable_watcher_users = issue.addable_watcher_users
          watchers.split(',').each do |watcher|
            begin
              #watcher_user = user_id_for_login!(watcher)
              watcher_user = find_user('watcher', watcher)
              if issue.watcher_users.include?(watcher_user)
                next
              end
              if addable_watcher_users.include?(watcher_user)
                issue.add_watcher(watcher_user)
              end
            rescue ActiveRecord::RecordNotFound
              if watcher_failed_count == 0
                @failed_count += 1
                @failed_issues[@failed_count] = row
              end
              watcher_failed_count += 1
              flash_message(:warning, "When trying to add watchers on issue #{@failed_count} below, User #{watcher} was not found")
            end
          end
        end
        next if watcher_failed_count > 0
      end

      begin
        issue.save!
        success = true
      rescue => e
        success = false
        unless @failed_first_error
          @failed_first_error = e.message
        end
      end

      #if (!issue.save)
      if (!success)
        # error log
        @failed_count += 1
        @failed_issues[@failed_count] = row
        flash_message(:warning, "The following data-validation errors occurred on issue #{@failed_count} in the list below")
        issue.errors.each do |attr, error_message|
          #flash_message(:warning, "&nbsp;&nbsp;"+error_message)
          begin
            begin
              column_name = l("field_" + attr.to_s)
            rescue
              column_name = l(attr.to_s)
            end
          rescue
            column_name = attr.to_s
          end
          flash_message(:warning, column_name + "&nbsp;" + error_message)
        end
      else
        if unique_field
          @issue_by_unique_attr[row[unique_field]] = issue
        end

        if send_emails
          if update_issue
            if Setting.notified_events.include?('issue_updated') && (!issue.current_journal.empty?)
              Mailer.deliver_issue_edit(issue.current_journal)
            end
          else
            if Setting.notified_events.include?('issue_added')
              Mailer.deliver_issue_add(issue)
            end
          end
        end

        # Issue relations
        begin
          IssueRelation::TYPES.each_pair do |rtype, rinfo|
            if !row[attrs_map[rtype]]
              next
            end
            other_issue = issue_for_unique_attr(unique_attr,row[attrs_map[rtype]],row)
            relations = issue.relations.select { |r| (r.other_issue(issue).id == other_issue.id) && (r.relation_type_for(issue) == rtype) }
            if relations.length == 0
              relation = IssueRelation.new( :issue_from => issue, :issue_to => other_issue, :relation_type => rtype )
              relation.save
            end
          end
        rescue NoIssueForUniqueValue
          if ignore_non_exist
            @skip_count += 1
            next
          end
        rescue MultipleIssuesForUniqueValue
          break
        end

        if journal
          journal
        end

        @handle_count += 1

      end

    end # do

    if @failed_issues.size > 0
      @failed_issues = @failed_issues.sort
      @headers = @failed_issues[0][1].headers
    end

    # Clean up after ourselves
    iip.delete

    # Garbage prevention: clean up iips older than 3 days
    ImportInProgress.delete_all(["created < ?",Time.new - 3*24*60*60])
  end

private

  def find_project
    @project = Project.find(params[:project_id])
  end

  def flash_message(type, text)
    flash[type] ||= ""
    flash[type] += "#{text}<br/>"
  end

  def find_user(attr, name, default_user = nil)
    if name
      user = @users ? @users[name]: User.find_by_login(name)
      if @check_non_exist_user && !user
        flash[:warning] = "#{attr}: Unknown user '#{name}'"
        user = ''
      end
    end
    user = default_user unless user
    user
  end

end
